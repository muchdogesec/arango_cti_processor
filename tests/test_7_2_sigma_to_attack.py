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
            "--relationship", "sigma-attack",
            "--stix2arango_note", "test07",
            "--ignore_embedded_relationships", "false"
        ], check=True)
        
        cls.db = client.db('arango_cti_processor_standard_tests_database', username=ARANGODB_USERNAME, password=ARANGODB_PASSWORD)

    def run_query(self, query):
        cursor = self.db.aql.execute(query)
        return [count for count in cursor]

    # test 1 Should return 3 results, the new and 2 old objects.
    def test_01_updated_object(self):
        query = """
        RETURN LENGTH(
          FOR doc IN sigma_rules_vertex_collection
              FILTER doc.id == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [3], f"Expected 3 documents, but found {result_count}.")

    # test 2 check new relationship objects generated for indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1 . Should be 0 as new object has no attack refs
    def test_02_check_old_objects_for_update(self):
        query = """
        RETURN LENGTH(
          FOR doc IN sigma_rules_edge_collection
              FILTER doc._is_latest == true
              AND doc.relationship_type == "detects"
              AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

    # test 3 check old relationship objects generated for indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1 . Should be 10 -- 5 in 7.0 and 6 in 7.1
    def test_03_check_new_objects_for_update(self):
        query = """
        RETURN LENGTH(
          FOR doc IN sigma_rules_edge_collection
              FILTER doc._is_latest == false
              AND doc.relationship_type == "detects"
              AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [11], f"Expected 11 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
