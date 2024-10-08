import os
import subprocess
import unittest
from arango import ArangoClient
from dotenv import load_dotenv
from stix2arango.stix2arango import Stix2Arango

from .upload import make_uploads

# Load environment variables
load_dotenv()

ARANGODB_USERNAME = os.getenv("ARANGODB_USERNAME", "root")
ARANGODB_PASSWORD = os.getenv("ARANGODB_PASSWORD", "")
ARANGODB_HOST_URL = os.getenv("ARANGODB_HOST_URL", "http://127.0.0.1:8529")
TESTS_DATABASE = "arango_cti_processor_standard_tests_database"
TEST_MODE = "cve-cwe"
STIX2ARANGO_NOTE = __name__.split('.')[-1]
IGNORE_EMBEDDED_RELATIONSHIPS = "false"
CREATED_MIN = "2024-01-01"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("nvd_cve", "tests/files/cve_bundle_controlled_created_times.json"),
                ("mitre_cwe", "tests/files/cwe-bundle-v4_13.json"),
            ], database="arango_cti_processor_standard_tests", delete_db=True, 
            host_url=ARANGODB_HOST_URL, password=ARANGODB_PASSWORD, username=ARANGODB_USERNAME, stix2arango_note=STIX2ARANGO_NOTE)
        print(f'======Test bundles uploaded successfully======')
        # Run the arango_cti_processor.py script
        subprocess.run([
            "python3", "arango_cti_processor.py",
            "--database", TESTS_DATABASE,
            "--relationship", TEST_MODE,
            "--stix2arango_note", STIX2ARANGO_NOTE,
            "--ignore_embedded_relationships", IGNORE_EMBEDDED_RELATIONSHIPS,
            "--created_min", CREATED_MIN
        ], check=True)
        print(f'======arango_cti_processor run successfully======')
        
        cls.db = client.db('arango_cti_processor_standard_tests_database', username=ARANGODB_USERNAME, password=ARANGODB_PASSWORD)

    def run_query(self, query):
        cursor = self.db.aql.execute(query)
        return [count for count in cursor]

    # should still return 2 objects b/c these never update
    def test_01_auto_imported_objects(self):
        query = """
          FOR doc IN nvd_cve_vertex_collection
            FILTER doc._arango_cti_processor_note == "automatically imported object at script runtime"
            RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 2 Should return 0 SROs as this object modified time too low
    def test_02_object_should_not_process(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_edge_collection
          FILTER doc._arango_cti_processor_note == "cve-cwe"
          AND doc.source_ref == "vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
          AND doc._is_ref == false
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

    # test 3 Should return 1 SRO as this object contains 1 CPE
    def test_03_object_should_process(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_edge_collection
          FILTER doc._arango_cti_processor_note == "cve-cwe"
          AND doc.source_ref == "vulnerability--ff040ea3-f2d9-5d38-80ae-065a2db41e64"
          AND doc._is_ref == false
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [1], f"Expected 1 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()