import unittest
from analyzer import analyze_csv

SAMPLE = """timestamp,user,source_ip,event_type,details,process
2026-11-18T09:00:00Z,alex,10.0.0.5,login_success,Interactive login,explorer.exe
2026-11-18T09:15:00Z,admin,203.0.113.77,login_failed,Bad password,sshd
2026-11-18T09:16:00Z,admin,203.0.113.77,login_failed,Bad password,sshd
2026-11-18T09:17:00Z,admin,203.0.113.77,login_failed,Bad password,sshd
2026-11-18T09:18:00Z,admin,203.0.113.77,login_success,Accepted password,sshd
2026-11-18T09:20:00Z,admin,203.0.113.77,process_start,Encoded command,powershell.exe -EncodedCommand Zg==
"""

class AnalyzerTests(unittest.TestCase):
    def test_flags_repeated_failed_logins_and_following_success(self):
        result = analyze_csv(SAMPLE)
        kinds = {finding["type"] for finding in result["findings"]}
        self.assertIn("Brute-force pattern", kinds)
        self.assertIn("Success after failures", kinds)

    def test_flags_suspicious_encoded_powershell(self):
        result = analyze_csv(SAMPLE)
        self.assertTrue(any("Encoded PowerShell" in f["type"] for f in result["findings"]))

    def test_rejects_missing_required_columns(self):
        with self.assertRaises(ValueError):
            analyze_csv("timestamp,user\n2026-01-01,a\n")

if __name__ == "__main__":
    unittest.main()
