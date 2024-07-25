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
            "--relationship", "capec-attack",
            "--stix2arango_note", "test01",
            "--ignore_embedded_relationships", "false"
        ], check=True)
        
        cls.db = client.db('arango_cti_processor_standard_tests_database', username=ARANGODB_USERNAME, password=ARANGODB_PASSWORD)

    def run_query(self, query):
        cursor = self.db.aql.execute(query)
        return [count for count in cursor]

    # test 1 Should return 6 objects, the newest version, and 5 old ones.
    def test_01_updated_capec158(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_capec_vertex_collection
              FILTER doc.id == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [6], f"Expected 6 documents, but found {result_count}.")

    # test 2 Should return 25 results. oldest version (1.0) of CAPEC158 had 4 ATT&CK references, old version 1.1 had 5 ATT&CK references, old version 1.2 had 6, 1.3 had 4, 1.4 had 6
    def test_02_updated_capec158_old_relationships(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_capec_edge_collection
              FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc._is_latest == false
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [25], f"Expected 25 documents, but found {result_count}.")

    # test 3 Should return 0 results because the new object has 0 ATT&CK references
    def test_03_updated_capec158_new_relationships(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_capec_edge_collection
              FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc._is_latest == true
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
