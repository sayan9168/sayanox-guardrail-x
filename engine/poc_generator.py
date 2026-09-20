"""
Sayanox Guardrail-X - Proof of Concept (PoC) Exploit Generator

Generates standalone executable scripts (Shell/Python) to reproduce
successful guardrail bypasses for verification and reporting.
"""

import os
import json
import shlex
from typing import Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExploitConfig:
    """Configuration for exploit script generation."""
    target_url: str
    payload: str
    method: str = "POST"
    headers: Optional[Dict[str, str]] = None
    model_name: Optional[str] = None
    system_prompt: Optional[str] = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {"Content-Type": "application/json"}


class PocGenerator:
    """
    Generates standalone exploit scripts from successful attack payloads.
    
    Supports generation of:
    - Shell scripts (cURL based)
    - Python scripts (requests based)
    """
    
    def __init__(self, output_dir: str = "./exploits"):
        """
        Initialize the PoC Generator.
        
        Args:
            output_dir: Directory to save generated exploit scripts.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _escape_shell_arg(self, arg: str) -> str:
        """Safely escape arguments for shell usage."""
        return shlex.quote(arg)
    
    def _escape_python_string(self, s: str) -> str:
        """Safely escape strings for Python source code."""
        return json.dumps(s)
    
    def generate_curl_script(self, config: ExploitConfig, filename: Optional[str] = None) -> str:
        """
        Generate a standalone bash script using cURL.
        
        Args:
            config: Exploit configuration details.
            filename: Optional custom filename.
            
        Returns:
            Absolute path to the generated script.
        """
        if filename is None:
            filename = f"exploit_{hash(config.payload) % 10000}.sh"
        
        filepath = self.output_dir / filename
        
        # Build JSON payload dynamically based on common API structures
        body_data = {"messages": [{"role": "user", "content": config.payload}]}
        if config.system_prompt:
            body_data["system"] = config.system_prompt # Some APIs use this
            # Or inject into messages if standard OpenAI format
            body_data["messages"].insert(0, {"role": "system", "content": config.system_prompt})
        if config.model_name:
            body_data["model"] = config.model_name
            
        json_body = json.dumps(body_data, indent=2).replace('"', '\\"')
        
        header_str = " ".join([f"-H '{k}: {v}'" for k, v in config.headers.items()])
        
        script_content = f"""#!/bin/bash
# Sayanox Guardrail-X - Generated Exploit Script
# Target: {config.target_url}
# Method: {config.method}
# Description: Autonomous reproduction of successful guardrail bypass.

set -e

echo "[*] Executing Guardrail Bypass PoC..."
echo "[*] Target: {config.target_url}"

RESPONSE=$(curl -s -X {config.method} \\
  {header_str} \\
  -d "{json_body}" \\
  "{config.target_url}")

echo ""
echo "[*] Response received:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

if echo "$RESPONSE" | grep -q "refusal"; then
    echo "[!] Guardrail potentially active (detected 'refusal' keyword)."
    exit 1
else
    echo "[+] Potential bypass successful (no refusal keywords detected)."
    exit 0
fi
"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(script_content)
            
            os.chmod(filepath, 0o755)
            return str(filepath.absolute())
        except IOError as e:
            raise RuntimeError(f"Failed to write curl script: {e}")

    def generate_python_script(self, config: ExploitConfig, filename: Optional[str] = None) -> str:
        """
        Generate a standalone Python script using requests.
        
        Args:
            config: Exploit configuration details.
            filename: Optional custom filename.
            
        Returns:
            Absolute path to the generated script.
        """
        if filename is None:
            filename = f"exploit_{hash(config.payload) % 10000}.py"
        
        filepath = self.output_dir / filename
        
        # Construct body dict
        body_dict = {
            "messages": [
                {"role": "user", "content": config.payload}
            ]
        }
        if config.system_prompt:
            body_dict["messages"].insert(0, {"role": "system", "content": config.system_prompt})
        if config.model_name:
            body_dict["model"] = config.model_name
            
        body_json = json.dumps(body_dict, indent=4)
        headers_repr = repr(config.headers)
        
        script_content = f'''#!/usr/bin/env python3
"""
Sayanox Guardrail-X - Generated Python Exploit Script
Target: {config.target_url}
Method: {config.method}
"""

import requests
import json
import sys

TARGET_URL = "{config.target_url}"
HEADERS = {headers_repr}

PAYLOAD = {body_json}

def main():
    print(f"[*] Sending payload to {{TARGET_URL}}...")
    
    try:
        response = requests.request(
            method="{config.method}",
            url=TARGET_URL,
            headers=HEADERS,
            json=PAYLOAD,
            timeout=30
        )
        response.raise_for_status()
        
        print("[*] Response Status:", response.status_code)
        print("[*] Response Body:")
        try:
            print(json.dumps(response.json(), indent=2))
        except ValueError:
            print(response.text)
            
        # Simple heuristic check
        resp_text = response.text.lower()
        if "refusal" in resp_text or "cannot fulfill" in resp_text:
            print("[!] Guardrail potentially active.")
            sys.exit(1)
        else:
            print("[+] Potential bypass successful.")
            sys.exit(0)
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {{e}}")
        sys.exit(2)

if __name__ == "__main__":
    main()
'''
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(script_content)
            
            os.chmod(filepath, 0o755)
            return str(filepath.absolute())
        except IOError as e:
            raise RuntimeError(f"Failed to write python script: {e}")

    def generate_all(self, config: ExploitConfig, base_name: Optional[str] = None) -> Dict[str, str]:
        """
        Generate both Shell and Python exploit scripts.
        
        Args:
            config: Exploit configuration.
            base_name: Base name for the files.
            
        Returns:
            Dictionary mapping type to file path.
        """
        results = {}
        try:
            sh_path = self.generate_curl_script(config, filename=f"{base_name}_exploit.sh" if base_name else None)
            results['shell'] = sh_path
        except Exception as e:
            results['shell_error'] = str(e)
            
        try:
            py_path = self.generate_python_script(config, filename=f"{base_name}_exploit.py" if base_name else None)
            results['python'] = py_path
        except Exception as e:
            results['python_error'] = str(e)
            
        return results
