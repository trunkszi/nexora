import unittest

from pmu_verify import counters


class PmuAdmissionTest(unittest.TestCase):
    rows = "1000,,cycles:u,100000,100.00\n2000,,instructions:u,100000,100.00\n100,,branches:u,100000,100.00\n1,,branch-misses:u,100000,100.00\n"

    def test_accepts_process_counter_group(self):
        self.assertEqual(counters(self.rows)["cycles"]["value"], 1000)

    def test_rejects_nonfinite_and_multiplexed_values(self):
        for invalid in (self.rows.replace("1000,,", "nan,,"), self.rows.replace("100.00", "98.99"),
                        self.rows.replace("100.00", "nan")):
            with self.assertRaises(ValueError):
                counters(invalid)

    def test_requires_complete_unique_group(self):
        for invalid in (self.rows.splitlines()[0], self.rows + self.rows):
            with self.assertRaises(ValueError):
                counters(invalid)


if __name__ == "__main__":
    unittest.main()
