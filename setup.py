"""
Setup configuration for Mobscan package
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="mobscan",
    version="1.0.0",
    description="OWASP MASTG Automated Mobile Security Testing Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Security Team",
    author_email="security@mobscan.dev",
    url="https://github.com/mobscan/mobscan",
    license="MIT",
    packages=find_packages(exclude=["tests", "docs"]),
    install_requires=[
        "pyyaml>=6.0",
        "click>=8.1.0",
        "fastapi>=0.104.0",
        "uvicorn>=0.24.0",
        "requests>=2.31.0",
        "python-docx>=0.8.11",
        "reportlab>=4.0.7",
        "weasyprint>=59.0",
        "jinja2>=3.1.2",
        "pydantic>=2.5.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.12.0",
            "flake8>=6.1.0",
            "mypy>=1.7.0",
        ],
        "docs": [
            "sphinx>=7.2.0",
            "sphinx-rtd-theme>=2.0.0",
        ],
        "advanced": [
            "frida>=16.0.0",
            "androguard>=4.1.0",
            "plotly>=5.18.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "mobscan=mobscan.cli:main",
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    keywords="mobile security testing android ios apk ipa owasp mastg masvs",
    project_urls={
        "Documentation": "https://mobscan.readthedocs.io",
        "Source Code": "https://github.com/mobscan/mobscan",
        "Bug Tracker": "https://github.com/mobscan/mobscan/issues",
        "Changelog": "https://github.com/mobscan/mobscan/releases",
    },
    include_package_data=True,
)
