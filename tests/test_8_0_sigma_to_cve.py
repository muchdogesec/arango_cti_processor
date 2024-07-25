import os
import subprocess
import unittest
from arango import ArangoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

ARANGODB_USERNAME = os.getenv("ARANGODB_USERNAME")
ARANGODB_PASSWORD = os.getenv("ARANGODB_PASSWORD")
ARANGODB_HOST_URL = os.getenv("ARANGODB_HOST_URL")

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Run the arango_cti_processor.py script
        subprocess.run([
            "python3", "arango_cti_processor.py",
            "--database", "arango_cti_processor_standard_tests_database",
            "--relationship", "sigma-cve",
            "--stix2arango_note", "test08",
            "--ignore_embedded_relationships", "false"
        ], check=True)
        
        cls.db = client.db('arango_cti_processor_standard_tests_database', username=ARANGODB_USERNAME, password=ARANGODB_PASSWORD)

    def run_query(self, query):
        cursor = self.db.aql.execute(query)
        return [count for count in cursor]

    # should still return 2 objects b/c these never update
    def test_01_auto_imported_objects(self):
        query = """
          FOR doc IN sigma_rules_edge_collection
            FILTER doc._arango_cti_processor_note == "automatically imported object at script runtime"
            RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")


# test 2 Expecting 4 results (see test-data-research.md for info as to why).
# `indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1`
# links to `cve.2022.26134` (`vulnerability--b4fd2041-12ff-5a64-9c00-51ba39b29fe4`) and 
# `cve.2021.26084` (`vulnerability--ff040ea3-f2d9-5d38-80ae-065a2db41e64`)

    def test_02_check_generated_relationships(self):
        query = """
          FOR doc IN sigma_rules_edge_collection
              FILTER doc._is_latest == true
              AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
              AND doc.relationship_type == "detects"
              RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            ""
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")