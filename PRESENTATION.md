# GhostTrail: presentation notes

## 30-second introduction
“GhostTrail is a local digital-forensics triage prototype. It takes a structured export of security events and reconstructs them as a chronological trail. It correlates repeated failed logins with a later success and flags selected process patterns, then shows the evidence and why an analyst might review it. It helps organize investigation; it does not declare that a machine is compromised.”

## Problem and solution
During an incident, evidence is scattered across timestamps and event records. Reviewing rows one by one makes it easy to miss order and relationships. GhostTrail normalizes the supplied CSV rows, orders events by timestamp, applies a small set of explainable rules, and displays both the event sequence and finding evidence in one view.

## Demo script (about 2 minutes)
1. Start the program and open `http://127.0.0.1:8765`.
2. Click **Load demo incident**. Explain that all records are synthetic and the example IP is reserved for documentation.
3. Point to the 3 failed logins, the following successful login, and the encoded PowerShell process event.
4. Show the evidence panel. Click **Why review this?** to explain the rule and the analyst follow-up.
5. Download the investigation report and mention that it is useful as a handoff artifact.
6. Explain limitations: the demo reads only its documented CSV format, and pattern matches are leads—not proof.

## Walk through the logic
- **Input:** CSV records with timestamp, user, source IP, event type, details, and process.
- **Ordering:** parse rows and sort by the provided timestamp (ISO-8601 recommended).
- **Correlation:** group authentication failures by source IP. Three or more failures create a brute-force review lead. A later successful login from that source creates a higher-priority lead.
- **Process rules:** look for encoded PowerShell and a network/HTTP rundll32 invocation.
- **Output:** browser timeline, finding cards containing evidence and rationale, and a downloadable text report.

## Likely questions
**Does it prove the computer was hacked?** No. A heuristic is a signal to investigate. Legitimate admin activity can match these patterns; corroborate with original logs, process command line, account activity, endpoint telemetry, and known maintenance windows.

**Does it read Windows Event Viewer or Linux journal directly?** Not in this MVP. It uses a small documented CSV interchange format so that the end-to-end workflow can be demonstrated reliably. A future version could add parsers for Windows EVTX and Linux journald/syslog exports.

**Why use source IP for correlation?** It is a simple demonstration key that is present in common authentication logs. A production system should also correlate account, host, session, event IDs, and time windows, and handle NAT/VPN/shared infrastructure carefully.

**Can an attacker evade these rules?** Yes. This is a demonstration of transparent triage, not comprehensive detection. Attackers can change techniques and benign tools can resemble suspicious behavior.

**How is it safe/private?** The web server binds to loopback (`127.0.0.1`), uses Python's standard library, and requires no account or external service. Use sanitized logs; real logs may contain personal or sensitive operational data.

## Future improvements
Windows EVTX and Linux journald parsers; configurable time windows; host/account/session correlation; timezone normalization; source provenance and hash of input evidence; filtering/search; rule configuration; tests against labeled datasets; optional analyst annotations.

## Honest scope statement
“GhostTrail currently analyzes the provided CSV format. Direct Windows/Linux log ingestion, forensic chain-of-custody controls, and validated detection quality are future work.”
