import unittest
import sys
import os

class CustomTestResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.successes = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.successes.append(test)

class CustomTestRunner(unittest.TextTestRunner):
    def _makeResult(self):
        return CustomTestResult(self.stream, self.descriptions, self.verbosity)

if __name__ == '__main__':
    # Add the parent directory of the "tests" folder to the system path
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

    # Create a test loader
    loader = unittest.TestLoader()

    # List of test modules to run in order
    test_modules = [
        'tests.test_01_00_capec_to_attack',
        'tests.test_01_01_capec_to_attack',
        'tests.test_01_1_capec_to_attack',
        'tests.test_01_2_capec_to_attack',
        'tests.test_01_3_capec_to_attack',
        'tests.test_01_4_capec_to_attack',
        'tests.test_01_5_capec_to_attack',
        'tests.test_03_0_cwe_to_capec',
        'tests.test_03_1_cwe_to_capec',
        'tests.test_09_0_modified_min',
        'tests.test_09_1_created_min',
        'tests.test_10_0_ignore_embedded_relationships_f',
        'tests.test_10_1_ignore_embedded_relationships_f',
        'tests.test_10_2_ignore_embedded_relationships_f',
        'tests.test_11_0_ignore_embedded_relationships_t',
    ]

    # Load the test cases in order
    suites = [loader.loadTestsFromName(module) for module in test_modules]

    # Combine all the suites into a single test suite
    combined_suite = unittest.TestSuite(suites)

    # Run the test suite with the custom runner
    runner = CustomTestRunner(verbosity=2)
    result = runner.run(combined_suite)

