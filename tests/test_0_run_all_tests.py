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
        'tests.test_1_0_5_capec_to_attack',
        'tests.test_1_0_capec_to_attack',
        'tests.test_1_1_capec_to_attack',
        'tests.test_1_2_capec_to_attack',
        'tests.test_1_3_capec_to_attack',
        'tests.test_1_4_capec_to_attack',
        'tests.test_1_5_capec_to_attack',
        'tests.test_2_0_capec_to_cwe',
        'tests.test_2_1_capec_to_cwe',
        'tests.test_3_0_cwe_to_capec',
        'tests.test_3_1_cwe_to_capec',
        'tests.test_4_0_attack_to_capec',
        'tests.test_5_0_cve_to_cwe',
        'tests.test_5_1_cve_to_cwe',
        'tests.test_5_2_cve_to_cwe',
        'tests.test_6_0_cve_to_cpe',
        'tests.test_6_1_cve_to_cpe',
        'tests.test_6_2_cve_to_cpe',
        'tests.test_7_0_sigma_to_attack',
        'tests.test_7_1_sigma_to_attack',
        'tests.test_7_2_sigma_to_attack',
        'tests.test_8_0_sigma_to_cve',
        'tests.test_8_1_sigma_to_cve',
        'tests.test_8_2_sigma_to_cve',
        'tests.test_9_0_modified_min',
        'tests.test_9_1_created_min',
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

    # Print summary of results
    print("\nSummary:")
    print(f"Total tests run: {result.testsRun}")
    print(f"Successes: {len(result.successes)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    # Print details of failed tests
    if result.failures:
        print("\nFailed Tests:")
        for failed_test, traceback in result.failures:
            print(f"Test: {failed_test}")
            print(f"Traceback:\n{traceback}")

    # Print details of tests that raised errors
    if result.errors:
        print("\nErrored Tests:")
        for errored_test, traceback in result.errors:
            print(f"Test: {errored_test}")
            print(f"Traceback:\n{traceback}")
