"""Stage 7 binary pwn helper tests (specs 9, 10, 11, 12)."""

import os
import sys
import struct
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import binary_pwn
from tools.workspace import WorkspaceError


class TestCyclic(unittest.TestCase):
    def test_cyclic_length(self):
        self.assertEqual(len(binary_pwn.pwn_cyclic(100)), 100)
        self.assertEqual(len(binary_pwn.pwn_cyclic(0)), 0)

    def test_cyclic_find_known_offset(self):
        pattern = binary_pwn.pwn_cyclic(512)
        chunk = pattern[40:44]
        self.assertEqual(binary_pwn.pwn_cyclic_find(chunk), 40)

    def test_cyclic_find_not_found(self):
        self.assertEqual(binary_pwn.pwn_cyclic_find("ZZZZ"), -1)

    def test_cyclic_find_short_input(self):
        self.assertEqual(binary_pwn.pwn_cyclic_find("ab"), -1)

    def test_cyclic_invalid_length(self):
        with self.assertRaises(ValueError):
            binary_pwn.pwn_cyclic(-1)


class TestPackUnpack(unittest.TestCase):
    def test_pack_roundtrip_64le(self):
        packed = binary_pwn.pwn_pack(0x4011A6, 64, "little")
        self.assertEqual(packed, "a611400000000000")
        self.assertEqual(binary_pwn.pwn_unpack(packed, 64, "little"), 0x4011A6)

    def test_pack_roundtrip_32be(self):
        packed = binary_pwn.pwn_pack(0xDEADBEEF, 32, "big")
        self.assertEqual(packed, "deadbeef")
        self.assertEqual(binary_pwn.pwn_unpack(packed, 32, "big"), 0xDEADBEEF)

    def test_pack_bad_bits(self):
        with self.assertRaises(ValueError):
            binary_pwn.pwn_pack(1, 12)


class TestOffsetHelpers(unittest.TestCase):
    def test_crash_address_parsing(self):
        self.assertEqual(
            binary_pwn._crash_address("Segmentation fault at 0x41414141"),
            "0x41414141",
        )
        self.assertEqual(
            binary_pwn._crash_address("Program received signal SIGSEGV at 0x55555555"),
            "0x55555555",
        )
        self.assertIsNone(binary_pwn._crash_address("no crash here"))

    def test_offset_from_ascii_address(self):
        pattern = binary_pwn.pwn_cyclic(4096)
        # chunk at offset 40 as a little-endian ASCII overwrite
        chunk = pattern[40:44]
        addr = struct.unpack("<I", chunk.encode("ascii"))[0]
        self.assertEqual(
            binary_pwn._offset_from_address(hex(addr), pattern), 40
        )

    def test_offset_from_0e_style_address_returns_none(self):
        pattern = binary_pwn.pwn_cyclic(4096)
        self.assertIsNone(binary_pwn._offset_from_address("0x42424242", pattern))


class TestWorkspaceSafety(unittest.TestCase):
    def test_resolve_path_outside_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(WorkspaceError):
                binary_pwn._resolve_path("../outside", tmp)

    def test_resolve_path_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(WorkspaceError):
                binary_pwn._resolve_path("missing.bin", tmp)


class TestCommandDriven(unittest.TestCase):
    """Graceful degradation when system tools are unavailable."""

    def _patch_available(self, available=False):
        return patch.object(binary_pwn, "_command_available", return_value=available)

    def test_elf_info_missing_file_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "bin")
            with open(target, "wb") as f:
                f.write(b"not really an elf")
            with self._patch_available(False):
                out = binary_pwn.pwn_elf_info("bin", tmp)
        self.assertIn("not available", out)

    def test_elf_info_parses_file_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "bin")
            with open(target, "wb") as f:
                f.write(b"x")
            with self._patch_available(True), patch(
                "tools.binary_pwn._run",
                return_value=(0, "ELF 64-bit LSB executable, x86-64, dynamically linked, stripped", ""),
            ):
                out = binary_pwn.pwn_elf_info("bin", tmp)
        self.assertIn("64-bit", out)
        self.assertIn("little", out)
        self.assertIn("stripped", out)

    def test_find_win_function_no_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "bin")
            with open(target, "wb") as f:
                f.write(b"data")
            with self._patch_available(False):
                out = binary_pwn.pwn_find_win_function("bin", tmp)
        self.assertIn("No win/flag function", out)

    def test_crash_analyze_nonexecutable(self):
        # A plain data file should not be executed.
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "data.txt")
            with open(target, "w") as f:
                f.write("not an executable")
            out = binary_pwn.pwn_crash_analyze("data.txt", tmp)
        self.assertIn("not executable", out)

    def test_crash_analyze_runs_with_cyclic_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "fakebin")
            with open(target, "wb") as f:
                f.write(b"\x7fELF" + b"\x00" * 32)  # ELF magic
            os.chmod(target, 0o755)
            with patch("tools.binary_pwn._run") as m:
                m.return_value = (-11, "", "Segmentation fault (core dumped)")
                out = binary_pwn.pwn_crash_analyze("fakebin", tmp, input_length=128)
            # cyclic input must be passed on stdin
            call = m.call_args
            self.assertIsNotNone(call.kwargs.get("stdin_data"))
            self.assertIn("cyclic", out.lower())

    def test_verify_offset_reports_not_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "fakebin")
            with open(target, "wb") as f:
                f.write(b"\x7fELF" + b"\x00" * 32)
            os.chmod(target, 0o755)
            with patch("tools.binary_pwn._run") as m:
                m.return_value = (-11, "", "Segmentation fault")
                out = binary_pwn.pwn_verify_offset("fakebin", 40, tmp)
        self.assertIn("Verification run", out)

    def test_gadget_search_no_objdump(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "bin")
            with open(target, "wb") as f:
                f.write(b"x")
            with self._patch_available(False):
                out = binary_pwn.pwn_find_gadgets("bin", tmp)
        self.assertIn("not available", out)

    def test_format_string_analysis_no_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "bin")
            with open(target, "wb") as f:
                f.write(b"x")
            with self._patch_available(False):
                out = binary_pwn.pwn_format_string_analysis("bin", tmp)
        self.assertIn("Format-string analysis", out)


class TestPwnSession(unittest.TestCase):
    def test_validate_remote_blocks_metadata(self):
        from tools.pwn_session import _validate_remote
        self.assertIsNotNone(_validate_remote("169.254.169.254", 80))
        self.assertIsNotNone(_validate_remote("metadata.google.internal", 80))

    def test_validate_remote_blocks_private_by_default(self):
        from tools.pwn_session import _validate_remote
        self.assertIsNotNone(_validate_remote("10.0.0.5", 1337))
        self.assertIsNotNone(_validate_remote("192.168.1.1", 1337))

    def test_validate_remote_invalid_port(self):
        from tools.pwn_session import _validate_remote
        self.assertIsNotNone(_validate_remote("ctf.example.com", 99999))

    def test_session_requires_pwntools(self):
        from tools.pwn_session import PwnSessionManager
        mgr = PwnSessionManager()
        out = mgr.send("hello")
        self.assertIn("no active session", out.lower())

    def test_pwntools_status_reports_install_hint(self):
        from tools.pwn_session import pwntools_status
        status = pwntools_status()
        self.assertIn("pwntools", status)


if __name__ == "__main__":
    unittest.main()
