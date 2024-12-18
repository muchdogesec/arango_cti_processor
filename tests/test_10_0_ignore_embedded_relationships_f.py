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
                ("mitre_capec", "tests/files/actip-capec-condensed.json"),
                ("mitre_cwe", "tests/files/actip-cwe-condensed.json"),
            ], database="arango_cti_processor_standard_tests", delete_db=True, 
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

        self.assertEqual(result_count, [2], f"Expected 2 documents, but found {result_count}.")


# arango cti processed makes 2 cwe-capec SROs, inside these SROs are a total of 3 embedded relationships (each has 1 created_by_ref and 2 object_marking_refs) so expect 6 total

    def test_02_count_is_ref(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_cwe_edge_collection
            FILTER doc._arango_cti_processor_note == "cwe-capec"
            AND doc._is_ref == true
            RETURN doc
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [6], f"Expected 6 documents, but found {result_count}.")

# check id of one of the generate objects
# `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` created-by+mitre_cwe_edge_collection/relationship--3e117c5b-65ea-5364-9447-905646aad09d+mitre_cwe_vertex_collection/identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3 = 47570226-cefc-5d1d-be1d-eac102751c7f

    def test_03_count_is_ref_object1(self):
        query = """
          FOR doc IN mitre_cwe_edge_collection
            FILTER doc._arango_cti_processor_note == "cwe-capec"
            LIMIT 1
            RETURN [{
                "created_by_ref": doc.created_by_ref,
                "object_marking_refs": doc.object_marking_refs,
                "_arango_cti_processor_note": doc._arango_cti_processor_note,
                "_is_latest": doc._is_latest
            }]
        """
        result_count = self.run_query(query)
        expected_ids = [
              [
                {
                  "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
                  "object_marking_refs": [
                    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
                  ],
                  "_arango_cti_processor_note": "cwe-capec",
                  "_is_latest": True
                }
              ]
            ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
