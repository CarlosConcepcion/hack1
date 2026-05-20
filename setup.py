from setuptools import setup, find_packages

setup(
    name="netaudit",
    version="1.0.0",
    description="NetAudit - Network Traffic Analyzer for Security Audits",
    author="Security Auditor",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "scapy>=2.5.0",
        "rich>=13.0.0",
        "click>=8.1.0",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "netaudit=netaudit.cli:cli",
        ],
    },
    python_requires=">=3.8",
)
