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
TEST_MODE = "cwe-capec"
IGNORE_EMBEDDED_RELATIONSHIPS = "true"
CREATED_MIN = "2020-01-01"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("mitre_capec", "tests/files/actip-stix-capec-v3_9.json"),
                ("mitre_cwe", "tests/files/actip-cwe-capec-controlled_created_times.json"),
            ], database="arango_cti_processor_standard_tests", delete_db=True, 
            host_url=ARANGODB_HOST_URL, password=ARANGODB_PASSWORD, username=ARANGODB_USERNAME)
        print(f'======Test bundles uploaded successfully======')
        # Run the arango_cti_processor.py script
        subprocess.run([
            "python3", "arango_cti_processor.py",
            "--database", TESTS_DATABASE,
            "--relationship", TEST_MODE,
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
          FOR doc IN mitre_cwe_vertex_collection
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
          FOR doc IN mitre_cwe_edge_collection
          FILTER doc._arango_cti_processor_note == "cwe-capec"
          AND doc.source_ref == "weakness--94110a45-2221-5fb5-aa09-322b8dfc4b6a"
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
          FOR doc IN mitre_cwe_edge_collection
          FILTER doc._arango_cti_processor_note == "cwe-capec"
          AND doc.source_ref == "weakness--416c9a7c-c45d-5f4e-8cf0-e38718a13370"
          AND doc._is_ref == false
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [1], f"Expected 1 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()