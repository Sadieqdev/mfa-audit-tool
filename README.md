# MFA Security Assessment Tool

A non-destructive, authorized-use CLI tool for auditing Multi-Factor
Authentication (MFA) implementations against NIST SP 800-63B, OWASP Top 10,
and MITRE ATT&CK.

## ⚠️ Ethical use

This tool is for **authorized security assessments only**. You must have
explicit written permission from the system owner. It performs no
exploitation, credential attacks, or social engineering.

## Install

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .