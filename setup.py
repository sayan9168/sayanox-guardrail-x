#!/usr/bin/env python3
"""
Sayanox Guardrail-X - Setup Script

Production-grade setup configuration for PyPI distribution.
Installs the sayanox-guardrail-x package and CLI entry point.

Author: Sayan Mahata / Sayanox Tech
License: MIT
"""

from setuptools import setup, find_packages
from pathlib import Path
import re

# Read README for long description
this_directory = Path(__file__).parent
long_description = ""
readme_path = this_directory / "README.md"
if readme_path.exists():
    long_description = readme_path.read_text(encoding="utf-8")

# Parse version from pyproject.toml or use default
version = "1.0.0"
pyproject_path = this_directory / "pyproject.toml"
if pyproject_path.exists():
    content = pyproject_path.read_text(encoding="utf-8")
    match = re.search(r'version\s*=\s*"([^"]+)"', content)
    if match:
        version = match.group(1)

# Core dependencies
install_requires = [
    "requests>=2.31.0",
    "python-dotenv>=1.0.0",
    "typing-extensions>=4.0.0",
]

# Development dependencies
extras_require = {
    "dev": [
        "pytest>=7.0.0",
        "pytest-cov>=4.0.0",
        "black>=23.0.0",
        "isort>=5.12.0",
        "flake8>=6.0.0",
        "mypy>=1.0.0",
    ],
    "docs": [
        "mkdocs>=1.5.0",
        "mkdocs-material>=9.0.0",
    ],
}

setup(
    name="sayanox-guardrail-x",
    version=version,
    author="Sayan Mahata",
    author_email="sayanox@proton.me",
    maintainer="Sayanox Tech",
    maintainer_email="sayanox@proton.me",
    description="Autonomous AI Red-Teaming Engine for discovering prompt injections, guardrail bypasses, and system leaks in target LLMs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sayanox/guardrail-x",
    project_urls={
        "Bug Tracker": "https://github.com/sayanox/guardrail-x/issues",
        "Documentation": "https://github.com/sayanox/guardrail-x#readme",
        "Source Code": "https://github.com/sayanox/guardrail-x",
        "Changelog": "https://github.com/sayanox/guardrail-x/releases",
    },
    packages=find_packages(
        where=".",
        include=["cli", "config", "engine*", "reports*"],
    ),
    package_data={
        "*": ["*.md", "*.txt", "*.json"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Software Development :: Testing",
    ],
    keywords=[
        "ai-security",
        "red-teaming",
        "llm-security",
        "prompt-injection",
        "guardrail-evaluation",
        "adversarial-testing",
        "ai-safety",
        "cybersecurity",
        "llm-testing",
        "security-audit",
    ],
    python_requires=">=3.9",
    install_requires=install_requires,
    extras_require=extras_require,
    entry_points={
        "console_scripts": [
            "sayanox-guardrail-x=cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    license="MIT",
    license_files=["LICENSE"],
)
