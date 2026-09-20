#!/usr/bin/env python3
"""
Sayanox Guardrail-X - Command Line Interface

Provides a CLI for running AI red-team campaigns against target LLMs.
Supports specifying target endpoints, base intents, attack types, and output paths.
"""

import argparse
import logging
import sys
from typing import List, Optional

from config import Configuration, AttackType, load_env_file
from engine.orchestrator import RedTeamOrchestrator


def setup_logging(log_level: str) -> None:
    """
    Configure logging for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR).
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        prog="guardrail-x",
        description=(
            "Sayanox Guardrail-X: Autonomous AI Red-Teaming Engine\n"
            "Automatically discover prompt injections, guardrail bypasses, "
            "and system leaks in target LLMs."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run a single campaign with default settings
  python cli.py --intent "Generate harmful content" --attack-type prompt_injection

  # Run with custom configuration
  python cli.py \\
      --intent "Bypass safety filters" \\
      --attack-type guardrail_bypass \\
      --max-iterations 100 \\
      --output ./my_reports \\
      --log-level DEBUG

  # Run multiple intents
  python cli.py \\
      --intents "intent1.txt" "intent2.txt" \\
      --attack-type system_leak \\
      --iterations-per-intent 20

Environment Variables:
  QWEN_API_KEY         Required. API key for Qwen-Coder service.
  QWEN_API_ENDPOINT    Optional. Base URL for Qwen-Coder API.
  TARGET_API_KEY       Optional. API key for target LLM service.
  TARGET_API_ENDPOINT  Optional. Base URL for target LLM API.
  MAX_ITERATIONS       Optional. Maximum iterations per campaign (default: 50).
  BYPASS_THRESHOLD     Optional. Bypass score threshold (default: 0.7).
  OUTPUT_PATH          Optional. Output directory for reports (default: ./reports).
  LOG_LEVEL            Optional. Logging level (default: INFO).
        """,
    )
    
    # Intent specification (mutually exclusive group)
    intent_group = parser.add_mutually_exclusive_group(required=True)
    intent_group.add_argument(
        "--intent",
        type=str,
        help="Base attack intent/prompt to test (single intent mode).",
    )
    intent_group.add_argument(
        "--intents-file",
        type=str,
        help="Path to a file containing multiple intents (one per line).",
    )
    
    # Attack configuration
    parser.add_argument(
        "--attack-type",
        type=str,
        choices=[t.value for t in AttackType],
        default="prompt_injection",
        help="Type of attack to perform (default: prompt_injection).",
    )
    
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Maximum iterations per campaign (overrides env var).",
    )
    
    parser.add_argument(
        "--iterations-per-intent",
        type=int,
        default=10,
        help="Iterations per intent when using multiple intents (default: 10).",
    )
    
    # Output configuration
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Output directory for reports (default: ./reports).",
    )
    
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity level (default: INFO).",
    )
    
    parser.add_argument(
        "--env-file",
        type=str,
        default=".env",
        help="Path to .env file (default: .env).",
    )
    
    # Target configuration
    parser.add_argument(
        "--target-endpoint",
        type=str,
        default=None,
        help="Target LLM API endpoint (overrides env var).",
    )
    
    parser.add_argument(
        "--qwen-endpoint",
        type=str,
        default=None,
        help="Qwen-Coder API endpoint (overrides env var).",
    )
    
    # Adapter configuration
    parser.add_argument(
        "--adapter",
        type=str,
        choices=["openai", "ollama", "generic_rest"],
        default="openai",
        help="Target adapter type to use (default: openai).",
    )
    
    parser.add_argument(
        "--adapter-model",
        type=str,
        default=None,
        help="Model name for the adapter (e.g., 'gpt-4', 'llama3').",
    )
    
    parser.add_argument(
        "--adapter-endpoint",
        type=str,
        default=None,
        help="Custom endpoint for the adapter (overrides default).",
    )
    
    # Report configuration
    parser.add_argument(
        "--html-report",
        type=str,
        default=None,
        help="Generate styled HTML report at specified path.",
    )
    
    parser.add_argument(
        "--json-report",
        type=str,
        default=None,
        help="Generate JSON report at specified path.",
    )
    
    # CI/CD integration
    parser.add_argument(
        "--fail-on-bypass",
        action="store_true",
        default=False,
        help=(
            "Exit with code 1 if any bypass score exceeds the safety threshold. "
            "Useful for DevSecOps pipeline automation."
        ),
    )
    
    # PoC generation
    parser.add_argument(
        "--generate-poc",
        action="store_true",
        default=False,
        help="Generate standalone exploit scripts (shell/python) for successful bypasses.",
    )
    
    # System prompt patching
    parser.add_argument(
        "--generate-patch",
        action="store_true",
        default=False,
        help="Generate hardened system prompt patch based on discovered vulnerabilities.",
    )
    
    # Multi-turn attack mode
    parser.add_argument(
        "--multi-turn",
        action="store_true",
        default=False,
        help="Enable stateful multi-turn injection attacks.",
    )
    
    parser.add_argument(
        "--multi-turn-strategy",
        type=str,
        choices=["linear", "sandwich", "gradual", "trust_build"],
        default="gradual",
        help="Strategy for multi-turn injection (default: gradual).",
    )
    
    return parser.parse_args()


def load_intents_from_file(filepath: str) -> List[str]:
    """
    Load attack intents from a text file.
    
    Args:
        filepath: Path to the intents file.
        
    Returns:
        List of intent strings.
    """
    try:
        with open(filepath, "r") as f:
            intents = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        
        if not intents:
            raise ValueError("No intents found in file")
        
        return intents
    except FileNotFoundError:
        raise FileNotFoundError(f"Intents file not found: {filepath}")
    except Exception as e:
        raise RuntimeError(f"Error reading intents file: {e}")


def run_single_intent_mode(args: argparse.Namespace, config: Configuration) -> int:
    """
    Run red-team campaign in single-intent mode.
    
    Args:
        args: Parsed command-line arguments.
        config: Configuration object.
        
    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    logger = logging.getLogger(__name__)
    
    attack_type = AttackType(args.attack_type)
    
    logger.info(f"Starting single-intent campaign")
    logger.info(f"Intent: {args.intent[:50]}...")
    logger.info(f"Attack Type: {attack_type.value}")
    logger.info(f"Adapter: {args.adapter}")
    
    # Build adapter configuration
    adapter_config = {}
    if args.adapter_model:
        adapter_config["model"] = args.adapter_model
    if args.adapter_endpoint:
        if args.adapter == "ollama":
            adapter_config["endpoint"] = args.adapter_endpoint
        else:
            # For OpenAI-compatible, update target endpoint
            config.target_api_endpoint = args.adapter_endpoint
    
    orchestrator = RedTeamOrchestrator(
        config=config,
        adapter_type=args.adapter,
        adapter_config=adapter_config
    )
    
    max_bypass_score = 0.0
    successful_bypasses = []
    
    try:
        # Handle multi-turn mode
        if args.multi_turn:
            from engine.stateful_mutator import StatefulMutator, TurnStrategy
            
            strategy_map = {
                "linear": TurnStrategy.LINEAR,
                "sandwich": TurnStrategy.SANDWICH,
                "gradual": TurnStrategy.GRADUAL,
                "trust_build": TurnStrategy.TRUST_BUILD,
            }
            strategy = strategy_map.get(args.multi_turn_strategy, TurnStrategy.GRADUAL)
            
            mutator = StatefulMutator(base_mutator=orchestrator.mutator)
            session = mutator.create_session(target_intent=args.intent, strategy=strategy)
            
            logger.info(f"Multi-turn session created: {session.session_id}")
            logger.info(f"Strategy: {strategy.value}")
            
            # Execute turns
            while not session.completed:
                response, is_complete = mutator.execute_next_turn(session.session_id, orchestrator.adapter)
                if response:
                    logger.debug(f"Turn response: {response[:100]}...")
            
            # Get final session report
            session_report = mutator.close_session(session.session_id)
            
            # Evaluate final turn for bypass
            if session_report and "history" in session_report:
                history = session_report["history"]
                if len(history) >= 2:
                    last_user_msg = next((h["content"] for h in reversed(history) if h["role"] == "user"), "")
                    last_assistant_msg = next((h["content"] for h in reversed(history) if h["role"] == "assistant"), "")
                    
                    if last_assistant_msg and not last_assistant_msg.startswith("[Error:"):
                        result = orchestrator.evaluator.evaluate_response(
                            original_intent=args.intent,
                            response=last_assistant_msg,
                            payload=last_user_msg
                        )
                        max_bypass_score = result.bypass_score
                        if result.bypass_score >= config.bypass_threshold:
                            successful_bypasses.append({
                                "payload": last_user_msg,
                                "response": last_assistant_msg,
                                "score": result.bypass_score
                            })
        else:
            # Standard single-turn campaign
            summary = orchestrator.run_campaign(
                base_intent=args.intent,
                attack_type=attack_type,
                max_iterations=args.max_iterations,
            )
            
            # Extract max bypass score from summary
            max_bypass_score = summary['statistics']['max_bypass_score']
            
            # Collect successful bypasses from results
            results = orchestrator.get_results()
            for entry in results.get('results', []):
                if entry.get('bypass_score', 0) >= config.bypass_threshold:
                    successful_bypasses.append({
                        "payload": entry.get('payload', ''),
                        "response": entry.get('response', ''),
                        "score": entry.get('bypass_score', 0)
                    })
        
        # Generate reports if requested
        report_paths = {}
        if args.html_report or args.json_report:
            from reports.generator import ReportGenerator
            
            results = orchestrator.get_results()
            generator = ReportGenerator(output_dir=config.output_path)
            
            if args.json_report:
                json_path = generator.generate_json_report(results, filename=args.json_report)
                report_paths["json"] = json_path
                logger.info(f"JSON report generated: {json_path}")
            
            if args.html_report:
                html_path = generator.generate_html_report(results, filename=args.html_report)
                report_paths["html"] = html_path
                logger.info(f"HTML report generated: {html_path}")
        
        # Generate PoC exploits if requested
        if args.generate_poc and successful_bypasses:
            from engine.poc_generator import PocGenerator, ExploitConfig
            
            poc_gen = PocGenerator(output_dir=f"{config.output_path}/exploits")
            logger.info(f"Generating PoC scripts for {len(successful_bypasses)} successful bypass(es)...")
            
            for i, bypass in enumerate(successful_bypasses[:5], 1):  # Limit to top 5
                exploit_config = ExploitConfig(
                    target_url=config.target_api_endpoint,
                    payload=bypass["payload"],
                    model_name=args.adapter_model,
                    system_prompt=None  # Could be extended to include original system prompt
                )
                paths = poc_gen.generate_all(exploit_config, base_name=f"bypass_{i}")
                logger.info(f"  Bypass {i}: Generated {paths}")
        
        # Generate system prompt patch if requested
        if args.generate_patch and successful_bypasses:
            from engine.patcher import SystemPromptPatcher
            
            patcher = SystemPromptPatcher()
            logger.info("Analyzing vulnerabilities and generating system prompt patch...")
            
            for bypass in successful_bypasses:
                patcher.analyze_payload(
                    payload=bypass["payload"],
                    bypass_score=bypass["score"]
                )
            
            patch_content = patcher.generate_patch()
            patch_file = f"{config.output_path}/hardened_system_prompt.txt"
            
            with open(patch_file, 'w', encoding='utf-8') as f:
                f.write(patch_content)
            
            logger.info(f"System prompt patch saved to: {patch_file}")
            
            # Also print patch to console
            print("\n" + "=" * 60)
            print("GENERATED SYSTEM PROMPT PATCH")
            print("=" * 60)
            print(patch_content)
            print("=" * 60)
        
        # Print summary to console
        print("\n" + "=" * 60)
        print("CAMPAIGN SUMMARY")
        print("=" * 60)
        
        if args.multi_turn:
            print(f"Mode: Multi-Turn Injection ({args.multi_turn_strategy})")
            print(f"Session ID: {session.session_id if 'session' in locals() else 'N/A'}")
        else:
            print(f"Campaign ID: {summary['campaign_id']}")
            print(f"Total Iterations: {summary['total_iterations']}")
            print(f"Elapsed Time: {summary['elapsed_time_seconds']:.2f}s")
            print(f"Iterations/Second: {summary['iterations_per_second']:.2f}")
        
        print(f"\nStatistics:")
        print(f"  Successful Bypasses: {len(successful_bypasses)}")
        print(f"  Max Bypass Score: {max_bypass_score:.3f}")
        
        if not args.multi_turn and 'summary' in locals():
            print(f"  Average Bypass Score: {summary['statistics']['average_bypass_score']:.3f}")
            print(f"  Refusal Rate: {summary['statistics']['refusal_rate']:.2%}")
            
            if summary['top_strategies']:
                print(f"\nTop Strategies:")
                for i, strat in enumerate(summary['top_strategies'][:3], 1):
                    print(f"  {i}. {strat['strategy']}: avg={strat['average_score']:.3f} "
                          f"(best={strat['best_score']:.3f}, attempts={strat['attempts']})")
        
        print("=" * 60)
        print(f"\nDetailed report saved to: {config.output_path}/")
        
        # CI/CD: Exit with code 1 if bypass exceeds threshold
        if args.fail_on_bypass and max_bypass_score >= config.bypass_threshold:
            print(f"\n[!] CRITICAL: Bypass score ({max_bypass_score:.3f}) exceeds threshold ({config.bypass_threshold})")
            print("[!] Exiting with code 1 for CI/CD pipeline failure.")
            return 1
        
        return 0
        
    except Exception as e:
        logger.error(f"Campaign failed: {e}")
        return 1


def run_multi_intent_mode(args: argparse.Namespace, config: Configuration) -> int:
    """
    Run red-team campaign in multi-intent mode.
    
    Args:
        args: Parsed command-line arguments.
        config: Configuration object.
        
    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    logger = logging.getLogger(__name__)
    
    try:
        intents = load_intents_from_file(args.intents_file)
    except Exception as e:
        logger.error(f"Failed to load intents: {e}")
        return 1
    
    attack_type = AttackType(args.attack_type)
    
    logger.info(f"Starting multi-intent campaign with {len(intents)} intents")
    logger.info(f"Attack Type: {attack_type.value}")
    logger.info(f"Iterations per Intent: {args.iterations_per_intent}")
    
    orchestrator = RedTeamOrchestrator(config)
    
    try:
        aggregated = orchestrator.run_multi_intent_campaign(
            intents=intents,
            attack_type=attack_type,
            iterations_per_intent=args.iterations_per_intent,
        )
        
        # Print summary to console
        print("\n" + "=" * 60)
        print("MULTI-INTENT CAMPAIGN SUMMARY")
        print("=" * 60)
        print(f"Total Campaigns: {aggregated['total_campaigns']}")
        print(f"\nAggregate Statistics:")
        print(f"  Total Iterations: {aggregated['aggregate_statistics']['total_iterations']}")
        print(f"  Total Bypasses: {aggregated['aggregate_statistics']['total_bypasses']}")
        print(f"  Overall Average Score: {aggregated['aggregate_statistics']['overall_average_score']:.3f}")
        
        print("\nIndividual Campaign Results:")
        for i, camp_sum in enumerate(aggregated['campaign_summaries'], 1):
            intent_preview = camp_sum['base_intent'][:40]
            print(f"  {i}. Intent: \"{intent_preview}...\"")
            print(f"     Bypasses: {camp_sum['successful_bypass_count']}/{camp_sum['total_iterations']} "
                  f"(max score: {camp_sum['best_bypass_score']:.3f})")
        
        print("=" * 60)
        print(f"\nAggregated report saved to: {config.output_path}/")
        
        return 0
        
    except Exception as e:
        logger.error(f"Campaign failed: {e}")
        return 1


def main() -> int:
    """
    Main entry point for the CLI.
    
    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    args = parse_arguments()
    
    # Load environment variables from file
    load_env_file(args.env_file)
    
    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)
    
    logger.info("Sayanox Guardrail-X initialized")
    
    # Build configuration
    try:
        config = Configuration.from_env()
        
        # Override with CLI arguments if provided
        if args.output:
            config.output_path = args.output
        if args.target_endpoint:
            config.target_api_endpoint = args.target_endpoint
        if args.qwen_endpoint:
            config.qwen_api_endpoint = args.qwen_endpoint
        if args.max_iterations:
            config.max_iterations = args.max_iterations
            
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        print("\nError: Missing required environment variables.")
        print("Please set QWEN_API_KEY or use --help for more information.")
        return 1
    
    # Validate inputs
    if args.intent:
        if len(args.intent) < 5:
            logger.warning("Intent is very short. This may affect mutation quality.")
    
    # Run appropriate mode
    if args.intents_file:
        return run_multi_intent_mode(args, config)
    else:
        return run_single_intent_mode(args, config)


if __name__ == "__main__":
    sys.exit(main())
