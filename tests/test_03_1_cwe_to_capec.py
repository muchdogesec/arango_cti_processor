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

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("mitre_cwe", "tests/files/actip-cwe-capec-update-1.json"),
            ], database="arango_cti_processor_standard_tests", delete_db=False, 
            host_url=ARANGODB_HOST_URL, password=ARANGODB_PASSWORD, username=ARANGODB_USERNAME)
        print(f'======Test bundles uploaded successfully======')
        # Run the arango_cti_processor.py script
        subprocess.run([
            "python3", "arango_cti_processor.py",
            "--database", TESTS_DATABASE,
            "--relationship", TEST_MODE,
            "--ignore_embedded_relationships", IGNORE_EMBEDDED_RELATIONSHIPS
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

    # test 2 Should return 2 results, the new and the old object.
    def test_02_cwe521_versions(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_cwe_vertex_collection
              FILTER doc.id == "weakness--de02e88c-42c5-5ddf-b5d1-1c8aeac79926"
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [2], f"Expected 2 documents, but found {result_count}.")

    # test 3 Should return 9 results, the old sro objects in 3.0.
    def test_03_cwe521_old_rel_versions(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_cwe_edge_collection
              FILTER doc.source_ref == "weakness--de02e88c-42c5-5ddf-b5d1-1c8aeac79926"
              AND doc._is_latest == false
              AND doc._arango_cti_processor_note == "cwe-capec"
              AND doc._is_ref == false
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [9], f"Expected 9 documents, but found {result_count}.")

    # test 4 Should return 10 results, inc. the newly added object
    def test_04_cwe521_new_rel_versions(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_cwe_edge_collection
              FILTER doc.source_ref == "weakness--de02e88c-42c5-5ddf-b5d1-1c8aeac79926"
              AND doc._is_latest == true
              AND doc._arango_cti_processor_note == "cwe-capec"
              AND doc._is_ref == false
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [10], f"Expected 10 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
