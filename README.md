# GhostTrail — Digital Forensics Timeline Reconstructor

A local-only, dependency-free web demo that reads a documented CSV event format, sorts events into a timeline, applies transparent triage rules, and exports a plain-text investigation report. It is an educational prototype, not a forensic suite or proof of compromise.

## Run it (Windows)
1. Install Python 3 if it is not already installed.
2. Open this folder in File Explorer and double-click `run_ghosttrail.bat` (or use `python server.py` in Command Prompt).
3. Open `http://127.0.0.1:8765` in your browser.
4. Click **Load demo incident**. Explore the event timeline and evidence, then download the report.
5. Stop the server with Ctrl+C in the command window.

No packages, internet connection, accounts, or external systems are needed. The server binds only to `127.0.0.1` (this computer).

## CSV input contract
Required headers: `timestamp,user,source_ip,event_type,details,process`. One event per row. Example types include `login_failed`, `login_success`, and `process_start`. Keep timestamps consistently formatted (ISO-8601 recommended). The included data is synthetic; `203.0.113.77` is a documentation-only reserved IP.

## Detection rules (explainable heuristics)
- **Brute-force pattern:** at least 3 failed logins from the same source IP in the imported dataset.
- **Success after failures:** successful login from an IP after at least 3 earlier failures in this dataset.
- **Encoded PowerShell:** process/details mention PowerShell and `-EncodedCommand` or `-enc`.
- **Unusual rundll32:** rundll32 invocation includes an HTTP or network-path indicator.

These rules are deliberately simple and can generate false positives. Findings are review leads; they do not establish attacker identity, causation, or compromise. The application does not inspect the real Windows Event Log or Linux journal; this version analyzes the documented CSV format only.

## Presentation walkthrough
Use `PRESENTATION.md` for the project explanation, demo script, limitations, and likely questions.

## Verify
From this directory run `python -m unittest -v test_ghosttrail.py`.
