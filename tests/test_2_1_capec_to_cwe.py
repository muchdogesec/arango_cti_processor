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
            "--relationship", "capec-cwe",
            "--stix2arango_note", "test02",
            "--ignore_embedded_relationships", "false"
        ], check=True)
        
        cls.db = client.db('arango_cti_processor_standard_tests_database', username=ARANGODB_USERNAME, password=ARANGODB_PASSWORD)

    def run_query(self, query):
        cursor = self.db.aql.execute(query)
        return [count for count in cursor]

    # test 1 Should return 4 objects, the newest version, and 3 old ones.
    def test_01_auto_imported_objects(self):
        query = """
          FOR doc IN mitre_capec_vertex_collection
            FILTER doc._arango_cti_processor_note == "automatically imported object at script runtime"
            RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 2 Should return 4 results, as 4 objects in latest version of capec112
    def test_02_correct_relationship_capec112_latest(self):
        query = """
        RETURN COUNT(
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc.source_ref == "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"
              AND doc._arango_cti_processor_note == "capec-cwe"
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [4], f"Expected 4 documents, but found {result_count}.")

    # test 3 Should return 3 results, as 3 weakness objects in old version of capec112
    def test_03_correct_relationship_capec112_old(self):
        query = """
        RETURN COUNT(
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == false
              AND doc.source_ref == "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"
              AND doc._arango_cti_processor_note == "capec-cwe"
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [3], f"Expected 3 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()