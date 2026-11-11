import unittest

from gem5_verify import ALIASES, metrics, parse_stats, roi_stats


class Gem5AdmissionTest(unittest.TestCase):
    def sample(self, cycles=1000):
        return dict(cycles=cycles, idle=0, instructions=3 * cycles, ops=4 * cycles,
                    renamed=4.2 * cycles, rename_idle=0.1 * cycles, squash=0.01 * cycles,
                    branch_misses=0, memory_violations=0)

    def test_named_rename_slot_accounting(self):
        report = metrics([self.sample(1000), self.sample(2000), self.sample(3000)], 8)
        self.assertAlmostEqual(report["retiring_pct"], 50)
        self.assertAlmostEqual(report["bad_speculation_pct"], 3.5)
        self.assertAlmostEqual(report["frontend_bound_pct"], 10)
        self.assertAlmostEqual(report["backend_bound_pct"], 36.5)

    def test_rejects_phase_drift_and_ordering_failures(self):
        with self.assertRaises(ValueError):
            metrics([self.sample(1000), self.sample(2000), self.sample(4000)], 8)
        samples = [self.sample(1000), self.sample(2000), self.sample(3000)]
        samples[2]["memory_violations"] = 1
        with self.assertRaises(ValueError):
            metrics(samples, 8)

    def test_requires_complete_finite_epoch(self):
        rows = [f"system.cpu.{ALIASES[name][0]} {value}" for name, value in self.sample().items()]
        text = "Begin Simulation Statistics\n" + "\n".join(rows) + "\nEnd Simulation Statistics\n"
        self.assertEqual(parse_stats(text)["cycles"], 1000)
        self.assertEqual(roi_stats(text + text)["cycles"], 1000)
        for invalid_roi in (text, text + text + text):
            with self.assertRaises(ValueError):
                roi_stats(invalid_roi)
        for invalid in (text + text, text.replace("numCycles 1000", "numCycles nan"), text.replace(rows[3], "")):
            with self.assertRaises(ValueError):
                parse_stats(invalid)


if __name__ == "__main__":
    unittest.main()
