"""Stage 7 specialist tests: structured results, web specialists, binary specialists."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from specialists.base import EvidenceSnapshot, SpecialistResult, make_items
from specialists.web import WEB_SPECIALISTS
from specialists.binary import BINARY_SPECIALISTS


class TestSpecialistResult(unittest.TestCase):
    def test_to_report_contains_all_sections(self):
        r = SpecialistResult(
            specialist="web.sql_injection",
            hypothesis="test",
            confirmed_observations=["obs"],
            rejected_hypotheses=["rej"],
            raw_evidence=["raw"],
            flag_status="not_confirmed",
            recommended_steps=["step"],
            suggested_next_specialist="web.authentication",
        )
        report = r.to_report()
        for section in ("Specialist", "Hypothesis", "Confirmed observations",
                        "Rejected hypotheses", "raw evidence", "Flag status",
                        "Recommended low-risk", "next specialist"):
            self.assertIn(section, report)

    def test_flag_confirmed_passthrough(self):
        ev = EvidenceSnapshot(make_items([
            {"tool": "read_text_file", "output": "flag{stage7_specialist_flag}", "success": True},
        ]))
        r = SpecialistResult(specialist="x", hypothesis="h")
        status, value = ev.flag_status()
        self.assertEqual(status, "confirmed")
        self.assertEqual(value, "flag{stage7_specialist_flag}")


class TestEvidenceSnapshot(unittest.TestCase):
    def setUp(self):
        self.ev = EvidenceSnapshot(make_items([
            {"tool": "http_get", "output": "200 ok page", "success": True},
            {"tool": "http_post", "output": "error", "success": False},
        ]))

    def test_successful_filters_failures(self):
        self.assertEqual(len(self.ev.successful()), 1)
        self.assertIn("200 ok page", self.ev.successful_output())

    def test_has_tool(self):
        self.assertTrue(self.ev.has_tool("http_get"))
        self.assertFalse(self.ev.has_tool("nope"))

    def test_outputs_for(self):
        self.assertEqual(self.ev.outputs_for("http_post"), ["error"])


class TestWebSpecialists(unittest.TestCase):
    """Each web specialist must run on evidence and return structured results."""

    def _instantiate_all(self):
        return [cls() for cls in WEB_SPECIALISTS]

    def test_all_web_specialists_have_metadata(self):
        for s in self._instantiate_all():
            self.assertTrue(s.name.startswith("web."), s.name)
            self.assertEqual(s.category, "web")
            self.assertTrue(s.signals, s.name)

    def test_sql_injection_confirms_error(self):
        from specialists.web.sql_injection import SQLInjectionSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "http_post", "output": "You have an error in your SQL syntax near '1''", "success": True},
        ]))
        result = SQLInjectionSpecialist().run(ev, {"challenge_type": "web"})
        self.assertIsInstance(result, SpecialistResult)
        self.assertTrue(any("SQL error message" in o for o in result.confirmed_observations))
        self.assertTrue(any("DROP" in s.upper() or "never" in s.lower() for s in result.recommended_steps))

    def test_sql_injection_forbidden_statements_never_recommended(self):
        from specialists.web.sql_injection import SQLInjectionSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "http_get", "output": "normal page", "success": True},
        ]))
        result = SQLInjectionSpecialist().run(ev)
        joined = " ".join(result.recommended_steps).lower()
        self.assertNotIn("drop ", joined)
        self.assertNotIn("delete ", joined)
        self.assertNotIn("update ", joined)

    def test_jwt_decodes_claims(self):
        from specialists.web.jwt import JWTSpecialist, parse_jwt
        import base64, json
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"user": "alice", "role": "admin", "exp": 9999999999}).encode()).decode().rstrip("=")
        token = f"{header}.{payload}.sig"
        h, p, err = parse_jwt(token)
        self.assertIsNone(err)
        self.assertEqual(p["role"], "admin")
        ev = EvidenceSnapshot(make_items([
            {"tool": "analyze_headers", "output": f"authorization: Bearer {token}", "success": True},
        ]))
        result = JWTSpecialist().run(ev)
        self.assertTrue(any("role" in o for o in result.confirmed_observations))
        self.assertTrue(any("HS256" in o for o in result.confirmed_observations))

    def test_jwt_alg_none_detected(self):
        from specialists.web.jwt import JWTSpecialist
        import base64, json
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"role": "admin"}).encode()).decode().rstrip("=")
        token = f"{header}.{payload}."
        ev = EvidenceSnapshot(make_items([
            {"tool": "http_get", "output": f"cookie: session={token}", "success": True},
        ]))
        result = JWTSpecialist().run(ev)
        self.assertTrue(any("none" in o.lower() for o in result.confirmed_observations))

    def test_ssti_arithmetic_confirmed(self):
        from specialists.web.ssti import SSTISpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "http_post", "arguments": {"name": "{{7*7}}"},
             "output": "Hello 49", "success": True},
        ]))
        result = SSTISpecialist().run(ev, {"challenge_type": "web"})
        joined = " ".join(result.confirmed_observations)
        self.assertIn("49", joined)

    def test_ssti_rejects_without_signals(self):
        from specialists.web.ssti import SSTISpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "http_get", "output": "plain page", "success": True},
        ]))
        result = SSTISpecialist().run(ev)
        self.assertTrue(result.rejected_hypotheses)

    def test_file_inclusion_confirms_disclosure(self):
        from specialists.web.file_inclusion import FileInclusionSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "http_get", "arguments": {"url": "http://x/page=../../../../etc/passwd"},
             "output": "root:x:0:0:root:/root:/bin/bash", "success": True},
        ]))
        result = FileInclusionSpecialist().run(ev, {"challenge_type": "web"})
        joined = " ".join(result.confirmed_observations).lower()
        self.assertIn("disclosure", joined)
        self.assertIn("root:x:0:0", joined)

    def test_authentication_detects_login_and_cookies(self):
        from specialists.web.authentication import AuthenticationSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "extract_forms_from_page",
             "output": '<form><input type="password" name="password"></form>', "success": True},
            {"tool": "analyze_headers",
             "output": "set-cookie: sessionid=abc123; HttpOnly", "success": True},
        ]))
        result = AuthenticationSpecialist().run(ev, {"challenge_type": "web"})
        joined = " ".join(result.confirmed_observations).lower()
        self.assertIn("login form", joined)
        self.assertIn("sessionid", joined)

    def test_graphql_introspection_detected(self):
        from specialists.web.graphql import GraphQLSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "http_post", "output": '{"data":{"__schema":{"types":[]}}}', "success": True},
        ]))
        result = GraphQLSpecialist().run(ev)
        self.assertTrue(any("introspection" in o for o in result.confirmed_observations))

    def test_websocket_url_detected(self):
        from specialists.web.websocket import WebSocketSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "analyze_javascript_url",
             "output": "WebSocket URLs:\n- wss://ctf.example.com/ws", "success": True},
        ]))
        result = WebSocketSpecialist().run(ev)
        self.assertTrue(any("wss://ctf.example.com/ws" in o for o in result.confirmed_observations))

    def test_api_analysis_parses_js_report(self):
        from specialists.web.api_analysis import JavaScriptApiSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "analyze_javascript_url",
             "output": "Endpoints:\n- /admin/users\n\nSecrets/tokens:\n- sk-abcdef1234567890\n\nGraphQL endpoints:\n- /graphql",
             "success": True},
        ]))
        result = JavaScriptApiSpecialist().run(ev)
        joined = " ".join(result.confirmed_observations)
        self.assertIn("/admin/users", joined)
        self.assertIn("/graphql", joined)

    def test_upload_surface_detected(self):
        from specialists.web.upload_analysis import UploadAnalysisSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "extract_forms_from_page",
             "output": '<form enctype="multipart/form-data"><input type="file" accept=".jpg,.png"></form>', "success": True},
        ]))
        result = UploadAnalysisSpecialist().run(ev)
        self.assertTrue(any("upload" in o.lower() for o in result.confirmed_observations))

    def test_race_pattern_detected(self):
        from specialists.web.race_condition import RaceConditionSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "http_post",
             "output": "redeem coupon endpoint - single use", "success": True},
        ]))
        result = RaceConditionSpecialist().run(ev)
        self.assertTrue(any("coupon" in o.lower() for o in result.confirmed_observations))

    def test_php_juggling_detected(self):
        from specialists.web.php import PHPSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "read_text_file",
             "output": 'if (md5($pass) == "0e830400451993494058024219903391") { grant(); }',
             "success": True},
        ]))
        result = PHPSpecialist().run(ev)
        joined = " ".join(result.confirmed_observations)
        self.assertIn("0e", joined)

    def test_flag_in_evidence_confirmed_by_all(self):
        ev = EvidenceSnapshot(make_items([
            {"tool": "read_text_file", "output": "flag{stage7_web_flag}", "success": True},
        ]))
        for cls in WEB_SPECIALISTS:
            result = cls().run(ev)
            self.assertEqual(result.flag_status, "confirmed", cls.name)
            self.assertEqual(result.flag_value, "flag{stage7_web_flag}")


class TestBinarySpecialists(unittest.TestCase):
    def _instantiate_all(self):
        return [cls() for cls in BINARY_SPECIALISTS]

    def test_all_binary_specialists_have_metadata(self):
        for s in self._instantiate_all():
            self.assertTrue(s.name.startswith("binary."), s.name)
            self.assertEqual(s.category, "binary")
            self.assertTrue(s.signals, s.name)

    def test_triage_evidence_mode(self):
        from specialists.binary.triage import BinaryTriageSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "binary_file_info",
             "output": "ELF 64-bit LSB executable, x86-64, dynamically linked, stripped",
             "success": True},
            {"tool": "binary_strings",
             "output": "strings: /bin/sh gets win flag{stage7_bin}",
             "success": True},
        ]))
        result = BinaryTriageSpecialist().run(ev)
        joined = " ".join(result.confirmed_observations).lower()
        self.assertIn("64-bit", joined)
        self.assertIn("win", joined)
        self.assertEqual(result.flag_status, "confirmed")

    def test_buffer_overflow_offset_confirmed(self):
        from specialists.binary.buffer_overflow import BufferOverflowSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "binary_strings", "output": "gets(", "success": True},
            {"tool": "binary_checksec",
             "output": "Arch: amd64-64-little RELRO: Partial RELRO Stack: No canary found NX: NX enabled PIE: PIE enabled",
             "success": True},
            {"tool": "pwn_crash_analyze",
             "output": "Overwrite offset: 40 bytes", "success": True},
        ]))
        result = BufferOverflowSpecialist().run(ev)
        joined = " ".join(result.confirmed_observations)
        self.assertIn("gets", joined)
        self.assertIn("offset", joined)
        self.assertIn("40", joined)

    def test_ret2win_finds_win_function(self):
        from specialists.binary.ret2win import Ret2winSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "binary_symbols",
             "output": "00000000004011a6 T win\n00000000004011c0 T main", "success": True},
            {"tool": "pwn_crash_analyze",
             "output": "Overwrite offset: 56 bytes", "success": True},
            {"tool": "pwn_elf_info",
             "output": "Architecture: 64-bit\nEndianness: little", "success": True},
        ]))
        result = Ret2winSpecialist().run(ev)
        joined = " ".join(result.confirmed_observations)
        self.assertIn("win", joined)
        self.assertIn("0x4011a6", joined)

    def test_format_string_leak_detected(self):
        from specialists.binary.format_string import FormatStringSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "pwn_format_string_analysis",
             "output": "Format-function usage: printf", "success": True},
            {"tool": "pwn_session_recv",
             "output": "aaaa0x7ffc12345678 0x555555554000", "success": True},
        ]))
        result = FormatStringSpecialist().run(ev)
        joined = " ".join(result.confirmed_observations)
        self.assertIn("printf", joined)

    def test_rop_gadgets_detected(self):
        from specialists.binary.rop_analysis import RopAnalysisSpecialist
        ev = EvidenceSnapshot(make_items([
            {"tool": "pwn_find_gadgets",
             "output": "ROP gadgets for vuln:\n- pop rdi; ret @ 0x4011a6\n- ret @ 0x40101a", "success": True},
            {"tool": "pwn_got_plt",
             "output": "JUMP_SLOT puts @ 0x404018", "success": True},
        ]))
        result = RopAnalysisSpecialist().run(ev)
        joined = " ".join(result.confirmed_observations)
        self.assertIn("pop rdi; ret", joined)
        self.assertIn("puts", joined)

    def test_pwntools_runner_degrades_gracefully(self):
        from specialists.binary.pwntools_runner import PwntoolsRunnerSpecialist
        ev = EvidenceSnapshot([])
        result = PwntoolsRunnerSpecialist().run(ev)
        joined = " ".join(result.recommended_steps)
        self.assertTrue(result.confirmed_observations)  # availability status
        # Either pwntools available or a graceful message
        self.assertTrue(any("pwntools" in o.lower() for o in result.confirmed_observations))

    def test_flag_in_evidence_confirmed_by_all(self):
        ev = EvidenceSnapshot(make_items([
            {"tool": "read_text_file", "output": "flag{stage7_binary_flag}", "success": True},
        ]))
        for cls in BINARY_SPECIALISTS:
            result = cls().run(ev)
            self.assertEqual(result.flag_status, "confirmed", cls.name)


if __name__ == "__main__":
    unittest.main()
