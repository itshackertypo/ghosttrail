"""GhostTrail: explainable triage rules for a documented CSV event format."""
import csv
import io
from collections import Counter, defaultdict

REQUIRED = {"timestamp", "user", "source_ip", "event_type", "details", "process"}


def analyze_csv(text):
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or not REQUIRED.issubset(set(reader.fieldnames)):
        raise ValueError("CSV must include columns: " + ", ".join(sorted(REQUIRED)))
    events = []
    for line, row in enumerate(reader, start=2):
        if not row.get("timestamp"):
            continue
        row = {key: (value or "").strip() for key, value in row.items()}
        row["_line"] = line
        events.append(row)
    events.sort(key=lambda e: e["timestamp"])
    failures = Counter(e["source_ip"] for e in events if e["event_type"].lower() == "login_failed")
    findings = []
    seen = set()
    for event in events:
        ip = event["source_ip"]
        if event["event_type"].lower() == "login_failed" and ip and failures[ip] >= 3 and ip not in seen:
            findings.append({"severity":"high", "type":"Brute-force pattern", "timestamp":event["timestamp"], "evidence":f"{failures[ip]} failed login attempts from {ip} in this dataset.", "why":"Repeated authentication failures from one source can indicate password guessing.", "line":event["_line"]})
            seen.add(ip)
        if event["event_type"].lower() == "login_success" and ip and failures[ip] >= 3:
            # Only count successful login after first failure in time order.
            prior = sum(1 for x in events if x["source_ip"] == ip and x["event_type"].lower() == "login_failed" and x["timestamp"] <= event["timestamp"])
            if prior >= 3:
                findings.append({"severity":"critical", "type":"Success after failures", "timestamp":event["timestamp"], "evidence":f"Successful login for {event['user']} from {ip} after {prior} failures.", "why":"A successful authentication after repeated failures raises concern that an account may have been guessed or compromised.", "line":event["_line"]})
        proc = (event["process"] + " " + event["details"]).lower()
        if "powershell" in proc and ("-encodedcommand" in proc or " -enc " in proc):
            findings.append({"severity":"high", "type":"Encoded PowerShell execution", "timestamp":event["timestamp"], "evidence":f"Process: {event['process']}; details: {event['details']}", "why":"Encoded commands can conceal intent. This can be legitimate administration, so validate the command and user context.", "line":event["_line"]})
        if "rundll32" in proc and ("http" in proc or "\\\\" in proc):
            findings.append({"severity":"medium", "type":"Unusual rundll32 invocation", "timestamp":event["timestamp"], "evidence":f"Process: {event['process']}; details: {event['details']}", "why":"rundll32 loading from a remote or network path may be suspicious and merits review.", "line":event["_line"]})
    return {"events": events, "findings": findings, "summary": {"events":len(events), "findings":len(findings), "high_risk":sum(1 for f in findings if f["severity"] in ("high","critical"))}}
