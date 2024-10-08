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
TEST_MODE = "sigma-cve"
STIX2ARANGO_NOTE = __name__.split('.')[-1]
IGNORE_EMBEDDED_RELATIONSHIPS = "false"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("sigma_rules", "tests/files/sigma-rules-with-NO-cve.json"),
            ], database="arango_cti_processor_standard_tests", delete_db=False, 
            host_url=ARANGODB_HOST_URL, password=ARANGODB_PASSWORD, username=ARANGODB_USERNAME, stix2arango_note=STIX2ARANGO_NOTE)
        print(f'======Test bundles uploaded successfully======')
        # Run the arango_cti_processor.py script
        subprocess.run([
            "python3", "arango_cti_processor.py",
            "--database", TESTS_DATABASE,
            "--relationship", TEST_MODE,
            "--stix2arango_note", STIX2ARANGO_NOTE,
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
          FOR doc IN sigma_rules_vertex_collection
            FILTER doc._arango_cti_processor_note == "automatically imported object at script runtime"
            RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 2 Should return 3 objects, the new and the 2 old version of the indicator updated
    def test_02_check_object_versions(self):
        query = """
        RETURN LENGTH(
          FOR doc IN sigma_rules_vertex_collection
              FILTER doc.id == "indicator--c6e28172-84af-594d-b09a-565a10121fe0"
              RETURN [doc]
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [3], f"Expected 3 documents, but found {result_count}.")

    # test 3 checking the new relationships that should be generated for indicator--c6e28172-84af-594d-b09a-565a10121fe0 which should be 0 as all cves removed
    def test_03_check_generated_relationships_new(self):
        query = """
        RETURN LENGTH(
          FOR doc IN sigma_rules_edge_collection
              FILTER doc._is_latest == true
              AND doc.relationship_type == "detects"
              AND doc.source_ref == "indicator--c6e28172-84af-594d-b09a-565a10121fe0"
              AND doc._is_ref == false
              RETURN [doc]
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

    # test 4 checking the old relationships for indicator--c6e28172-84af-594d-b09a-565a10121fe0 (2 from 8.0 and 3 from 8.1, thus 5 total)
    def test_03_check_generated_relationships_new(self):
        query = """
        RETURN LENGTH(
          FOR doc IN sigma_rules_edge_collection
              FILTER doc._is_latest == false
              AND doc.relationship_type == "detects"
              AND doc.source_ref == "indicator--c6e28172-84af-594d-b09a-565a10121fe0"
              AND doc._is_ref == false
              RETURN [doc]
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [5], f"Expected 5 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()