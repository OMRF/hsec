@echo off
rem hsec - TPM-sealed secret store. Runs the PEP 723 script via uv.
uv run --script "%~dp0hsec.py" %*
