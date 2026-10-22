import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from php2shell_check import classify, parse_version, check_mitigations, main


class T(unittest.TestCase):
    def test_patched(self):
        for v in ["8.5.12", "8.4.27", "8.3.36", "8.2.35", "8.5.13"]:
            self.assertEqual(classify(parse_version(v))[0], "patched", v)

    def test_vulnerable(self):
        for v in ["8.5.11", "8.4.26", "8.3.35", "8.2.34"]:
            self.assertEqual(classify(parse_version(v))[0], "vulnerable", v)

    def test_branches(self):
        self.assertEqual(classify((8, 1, 30))[0], "backport-needed")
        self.assertEqual(classify((7, 4, 33))[0], "backport-needed")
        self.assertEqual(classify((7, 3, 0))[0], "eol-vulnerable")
        self.assertEqual(classify((9, 0, 0))[0], "unknown")

    def test_distro_suffix(self):
        self.assertEqual(parse_version("8.3.36-1ubuntu1"), (8, 3, 36))

    def test_mitigations(self):
        m = check_mitigations({"memory_limit": "-1", "session.upload_progress.enabled": "0"}, (8, 4, 1))
        self.assertTrue(all(x["applied"] for x in m))
        self.assertEqual(len(check_mitigations({}, (8, 5, 1))), 3)
        self.assertFalse(any(x["applied"] for x in check_mitigations({}, (8, 5, 1))))

    def test_exit_codes(self):
        self.assertEqual(main(["--version", "8.4.27"]), 0)
        self.assertEqual(main(["--version", "8.4.1"]), 1)
        self.assertEqual(main(["--version", "garbage"]), 2)


if __name__ == "__main__":
    unittest.main()
