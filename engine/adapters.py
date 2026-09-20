"""
Sayanox Guardrail-X - Target Adapters
======================================
Unified interface for interacting with various LLM backends.
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

logger = logging.getLogger(__name__)


@dataclass
class AdapterResponse:
    """Standardized response object from any adapter."""
    content: str
    raw_response: Dict[str, Any]
    latency_ms: float
    token_usage: Optional[Dict[str, int]] = None
    error: Optional[str] = None


class BaseAdapter(ABC):
    """Abstract base class for all target LLM adapters."""

    def __init__(self, endpoint: str, api_key: Optional[str] = None, timeout: float = 30.0):
        self.endpoint = endpoint
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"Authorization": f"Bearer {api_key}"})

    @abstractmethod
    def send_prompt(self, prompt: str, system_instruction: Optional[str] = None) -> AdapterResponse:
        """Send a prompt to the target model and return standardized response."""
        pass

    def _handle_request_error(self, error: Exception, context: str) -> AdapterResponse:
        """Centralized error handling for request failures."""
        logger.error(f"{context} failed: {str(error)}")
        error_msg = f"{type(error).__name__}: {str(error)}"
        return AdapterResponse(
            content="",
            raw_response={},
            latency_ms=0.0,
            error=error_msg
        )


class OpenAIAdapter(BaseAdapter):
    """Adapter for OpenAI and OpenAI-compatible REST endpoints."""

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        model: str = "gpt-4",
        timeout: float = 30.0,
        max_tokens: int = 1024
    ):
        super().__init__(endpoint, api_key, timeout)
        self.model = model
        self.max_tokens = max_tokens
        self.session.headers.update({
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        })

    def send_prompt(self, prompt: str, system_instruction: Optional[str] = None) -> AdapterResponse:
        """Send prompt to OpenAI-compatible endpoint."""
        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": 0.7
        }

        start_time = time.time()
        try:
            response = self.session.post(
                self.endpoint,
                json=payload,
                timeout=self.timeout
            )
            latency_ms = (time.time() - start_time) * 1000
            response.raise_for_status()
            data = response.json()

            content = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})

            return AdapterResponse(
                content=content,
                raw_response=data,
                latency_ms=latency_ms,
                token_usage={
                    "prompt_tokens": usage.get("prompt_tokens", 0),
                    "completion_tokens": usage.get("completion_tokens", 0),
                    "total_tokens": usage.get("total_tokens", 0)
                }
            )

        except Timeout as e:
            return self._handle_request_error(e, "OpenAIAdapter timeout")
        except ConnectionError as e:
            return self._handle_request_error(e, "OpenAIAdapter connection failed")
        except RequestException as e:
            return self._handle_request_error(e, "OpenAIAdapter request failed")
        except (KeyError, IndexError, ValueError) as e:
            logger.error(f"OpenAIAdapter JSON parsing error: {str(e)}")
            return AdapterResponse(
                content="",
                raw_response={},
                latency_ms=(time.time() - start_time) * 1000,
                error=f"JSON parsing error: {str(e)}"
            )


class OllamaAdapter(BaseAdapter):
    """Adapter for local Ollama instances via native API."""

    def __init__(
        self,
        endpoint: str = "http://localhost:11434/api/generate",
        model: str = "llama3",
        timeout: float = 60.0,
        options: Optional[Dict[str, Any]] = None
    ):
        # Ollama typically doesn't require an API key for local instances
        super().__init__(endpoint, api_key=None, timeout=timeout)
        self.model = model
        self.options = options or {
            "temperature": 0.7,
            "top_p": 0.9,
            "num_predict": 1024
        }
        self.session.headers.update({"Content-Type": "application/json"})

    def send_prompt(self, prompt: str, system_instruction: Optional[str] = None) -> AdapterResponse:
        """Send prompt to Ollama instance."""
        full_prompt = prompt
        if system_instruction:
            full_prompt = f"{system_instruction}\n\n{prompt}"

        payload = {
            "model": self.model,
            "prompt": full_prompt,
            "stream": False,
            "options": self.options
        }

        start_time = time.time()
        try:
            response = self.session.post(
                self.endpoint,
                json=payload,
                timeout=self.timeout
            )
            latency_ms = (time.time() - start_time) * 1000
            response.raise_for_status()
            data = response.json()

            content = data.get("response", "")
            
            # Ollama doesn't always provide token usage in non-streaming mode
            token_usage = None
            if "eval_count" in data or "prompt_eval_count" in data:
                token_usage = {
                    "prompt_tokens": data.get("prompt_eval_count", 0),
                    "completion_tokens": data.get("eval_count", 0),
                    "total_tokens": data.get("prompt_eval_count", 0) + data.get("eval_count", 0)
                }

            return AdapterResponse(
                content=content,
                raw_response=data,
                latency_ms=latency_ms,
                token_usage=token_usage
            )

        except Timeout as e:
            return self._handle_request_error(e, "OllamaAdapter timeout")
        except ConnectionError as e:
            return self._handle_request_error(e, "OllamaAdapter connection failed (is Ollama running?)")
        except RequestException as e:
            return self._handle_request_error(e, "OllamaAdapter request failed")
        except (KeyError, ValueError) as e:
            logger.error(f"OllamaAdapter JSON parsing error: {str(e)}")
            return AdapterResponse(
                content="",
                raw_response={},
                latency_ms=(time.time() - start_time) * 1000,
                error=f"JSON parsing error: {str(e)}"
            )


class GenericRESTAdapter(BaseAdapter):
    """
    Adapter for custom REST payloads.
    Allows full customization of request structure via config.
    """

    def __init__(
        self,
        endpoint: str,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        payload_template: Optional[Dict[str, Any]] = None,
        response_path: str = "content"  # JSONPath-like string to extract content
    ):
        super().__init__(endpoint, api_key, timeout)
        self.method = method.upper()
        self.custom_headers = headers or {}
        self.payload_template = payload_template or {"input": "{prompt}"}
        self.response_path = response_path
        
        # Update session headers
        for key, value in self.custom_headers.items():
            self.session.headers[key] = value
        if api_key and "Authorization" not in self.custom_headers:
            self.session.headers["Authorization"] = f"Bearer {api_key}"

    def _extract_value_by_path(self, data: Dict[str, Any], path: str) -> Any:
        """Extract value from nested dict using dot notation path."""
        keys = path.split(".")
        current = data
        try:
            for key in keys:
                if isinstance(current, dict):
                    current = current[key]
                elif isinstance(current, list) and key.isdigit():
                    current = current[int(key)]
                else:
                    raise KeyError(f"Invalid path segment: {key}")
            return current
        except (KeyError, IndexError, TypeError) as e:
            raise ValueError(f"Could not extract response at path '{path}': {str(e)}")

    def send_prompt(self, prompt: str, system_instruction: Optional[str] = None) -> AdapterResponse:
        """Send prompt using generic REST configuration."""
        # Build payload from template
        payload_str = str(self.payload_template)
        payload = eval(payload_str.replace("{prompt}", repr(prompt)).replace("{system}", repr(system_instruction or "")))
        
        # Alternative safer replacement
        payload = self._build_payload(prompt, system_instruction)

        start_time = time.time()
        try:
            response = self.session.request(
                method=self.method,
                url=self.endpoint,
                json=payload,
                timeout=self.timeout
            )
            latency_ms = (time.time() - start_time) * 1000
            response.raise_for_status()
            data = response.json()

            content = self._extract_value_by_path(data, self.response_path)

            return AdapterResponse(
                content=str(content),
                raw_response=data,
                latency_ms=latency_ms,
                token_usage=None  # Generic adapter cannot assume token structure
            )

        except Timeout as e:
            return self._handle_request_error(e, "GenericRESTAdapter timeout")
        except ConnectionError as e:
            return self._handle_request_error(e, "GenericRESTAdapter connection failed")
        except RequestException as e:
            return self._handle_request_error(e, "GenericRESTAdapter request failed")
        except (KeyError, ValueError, IndexError) as e:
            logger.error(f"GenericRESTAdapter extraction error: {str(e)}")
            return AdapterResponse(
                content="",
                raw_response={},
                latency_ms=(time.time() - start_time) * 1000,
                error=f"Response extraction error: {str(e)}"
            )

    def _build_payload(self, prompt: str, system_instruction: Optional[str]) -> Dict[str, Any]:
        """Safely build payload from template."""
        import json
        template_str = json.dumps(self.payload_template)
        template_str = template_str.replace("{prompt}", prompt.replace('"', '\\"'))
        if system_instruction:
            template_str = template_str.replace("{system}", system_instruction.replace('"', '\\"'))
        else:
            template_str = template_str.replace('"{system}"', 'null').replace("{system}", "null")
        
        try:
            return json.loads(template_str)
        except json.JSONDecodeError as e:
            logger.error(f"Payload template JSON error: {e}")
            return {"input": prompt}
