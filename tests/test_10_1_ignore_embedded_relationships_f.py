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
IGNORE_EMBEDDED_RELATIONSHIPS = "false"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("mitre_cwe", "tests/files/actip-cwe-condensed-update-1.json"),
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

    def test_01_relationship_object_creation(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_cwe_edge_collection
            FILTER doc._arango_cti_processor_note == "cwe-capec"
            AND doc._is_ref == false
            AND doc._is_latest == true
            RETURN doc
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [3], f"Expected 3 documents, but found {result_count}.")

    def test_02_count_is_ref_latest(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_cwe_edge_collection
            FILTER doc._arango_cti_processor_note == "cwe-capec"
            AND doc._is_ref == true
            AND doc._is_latest == true
            RETURN doc
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [9], f"Expected 9 documents, but found {result_count}.")

# expect same as 10.0

    def test_03_count_is_ref_latest_false(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_cwe_edge_collection
            FILTER doc._arango_cti_processor_note == "cwe-capec"
            AND doc._is_ref == true
            AND doc._is_latest == false
            RETURN doc
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [6], f"Expected 6 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
