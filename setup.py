from setuptools import setup, find_packages

setup(
    name="mfa-audit-tool",
    version="1.0.0",
    description="Multi-Factor Authentication Security Assessment Tool",
    author="Abubakar Umar Ali",
    packages=find_packages(),
    include_package_data=True,
    package_data={"mfa_audit": ["data/*.json", "templates/*.j2"]},
    install_requires=[
        "requests>=2.31.0",
        "urllib3>=2.0.0",
        "rich>=13.7.0",
        "jinja2>=3.1.0",
    ],
    entry_points={
        "console_scripts": [
            "mfa-audit=mfa_audit.cli:main",
        ],
    },
    python_requires=">=3.9",
)