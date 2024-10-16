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
TEST_MODE = "cve-epss"
STIX2ARANGO_NOTE = __name__.split('.')[-1]
IGNORE_EMBEDDED_RELATIONSHIPS = "false"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
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


    # test 2 Should return all the SROs generated by arango_cti_processor -- expected = 2 (2 for the CVEs with EPSS, nothing for the CVE with no EPSS)
    def test_02_arango_cti_processor_note(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_vertex_collection
          FILTER doc.type == "note"
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [2], f"Expected 2 documents, but found {result_count}.")

    # here we expect 3 results per note (the one imported for 2024-10-08, and the one added by the script for YESTERDAY, and the one NOW)
    def test_03_check_count_of_dates(self):
        query = """
          FOR doc IN nvd_cve_vertex_collection
            FILTER doc.type == "note"
            RETURN {
                id: doc.id,
                date_count: LENGTH(doc.x_epss)
            }
        """
        result_count = self.run_query(query)
        expected_ids = [
          {
            "id": "note--008cc7df-b92b-5753-9451-62a4588dccc1",
            "date_count": 2
          },
          {
            "id": "note--030ac571-6dab-5214-b0e3-0ee2c09e1ce5",
            "date_count": 2
          }
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")



if __name__ == '__main__':
    unittest.main()
