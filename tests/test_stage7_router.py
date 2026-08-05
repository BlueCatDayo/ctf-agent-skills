"""Stage 7 specialist router tests (spec 13)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from specialists.base import EvidenceSnapshot, Specialist, make_items
from specialists.router import RankedSpecialist, SpecialistRouter


class DummySpecialist(Specialist):
    name = "web.dummy"
    category = "web"
    description = "dummy"
    signals = ["dummy", "sql", "injection"]


class OtherSpecialist(Specialist):
    name = "binary.other"
    category = "binary"
    description = "other"
    signals = ["elf", "pwn", "readelf"]


class TestRouterRegistration(unittest.TestCase):
    def test_register_and_list(self):
        router = SpecialistRouter(min_score=0.1)
        router.register(DummySpecialist(min_score=0.1))
        router.register_many([OtherSpecialist(min_score=0.1)])
        self.assertEqual(len(router.all()), 2)
        self.assertIsNotNone(router.get("web.dummy"))
        router.unregister("web.dummy")
        self.assertIsNone(router.get("web.dummy"))

    def test_list_specialists_renders(self):
        router = SpecialistRouter()
        router.register(DummySpecialist())
        text = router.list_specialists()
        self.assertIn("web.dummy", text)


class TestRouterSelection(unittest.TestCase):
    def setUp(self):
        self.router = SpecialistRouter(min_score=0.2)
        self.router.register(DummySpecialist(min_score=0.2))
        self.router.register(OtherSpecialist(min_score=0.2))

    def test_select_ranks_by_evidence(self):
        ev = EvidenceSnapshot(make_items([
            {"tool": "http_post", "output": "SQL injection error in query", "success": True},
        ]))
        selected = self.router.select(ev, {"challenge_type": "web"})
        self.assertTrue(selected)
        self.assertEqual(selected[0].specialist.name, "web.dummy")

    def test_binary_profile_boosts_binary_category(self):
        ev = EvidenceSnapshot(make_items([
            {"tool": "binary_strings", "output": "elf pwn readelf strings", "success": True},
        ]))
        selected = self.router.select(ev, {"challenge_type": "binary"})
        self.assertTrue(selected)
        self.assertEqual(selected[0].specialist.name, "binary.other")

    def test_no_selection_below_threshold(self):
        ev = EvidenceSnapshot(make_items([
            {"tool": "list_files", "output": "some files", "success": True},
        ]))
        self.assertEqual(self.router.select(ev, {"challenge_type": "misc"}), [])

    def test_used_specialists_deprioritized(self):
        ev = EvidenceSnapshot(make_items([
            {"tool": "http_post", "output": "SQL injection error readelf pwn", "success": True},
        ]))
        selected = self.router.select(ev, {"challenge_type": "web"}, used=["web.dummy"])
        self.assertTrue(selected)
        self.assertNotEqual(selected[0].specialist.name, "web.dummy")

    def test_suggest_next_returns_single(self):
        ev = EvidenceSnapshot(make_items([
            {"tool": "http_post", "output": "sql injection", "success": True},
        ]))
        suggestion = self.router.suggest_next(ev, {"challenge_type": "web"})
        self.assertIsInstance(suggestion, RankedSpecialist)
        self.assertEqual(suggestion.specialist.name, "web.dummy")

    def test_max_suggestions_capped(self):
        router = SpecialistRouter(min_score=0.0, max_suggestions=1)
        router.register(DummySpecialist(min_score=0.0))
        router.register(OtherSpecialist(min_score=0.0))
        ev = EvidenceSnapshot(make_items([
            {"tool": "http_post", "output": "sql injection pwn readelf", "success": True},
        ]))
        self.assertEqual(len(router.select(ev, {"challenge_type": "web"})), 1)


class TestRealRouter(unittest.TestCase):
    def test_all_registered_specialists_load(self):
        from specialists.binary import BINARY_SPECIALISTS
        from specialists.web import WEB_SPECIALISTS

        router = SpecialistRouter(min_score=0.2)
        for cls in WEB_SPECIALISTS + BINARY_SPECIALISTS:
            router.register(cls(min_score=0.2))
        self.assertEqual(len(router.all()), len(WEB_SPECIALISTS) + len(BINARY_SPECIALISTS))

        ev = EvidenceSnapshot(make_items([
            {"tool": "http_post", "output": "You have an error in your SQL syntax", "success": True},
        ]))
        top = router.suggest_next(ev, {"challenge_type": "web"})
        self.assertIsNotNone(top)
        self.assertEqual(top.specialist.name, "web.sql_injection")


if __name__ == "__main__":
    unittest.main()
