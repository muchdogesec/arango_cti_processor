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
TEST_MODE = "cve-cpe"
STIX2ARANGO_NOTE = __name__.split('.')[-1]
IGNORE_EMBEDDED_RELATIONSHIPS = "false"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("nvd_cve", "tests/files/condensed_cpe_bundle-update-1.json"),
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

# indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6 is updated. Used to have 2 patterns, so now has 3
# 2 old SROs and # 3 latest SROs will now exist.
# each creates 3 _is_ref SROS, so thus +3 _is_ref SROS from test 10.1

    def test_01_count_is_ref_latest(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_edge_collection
            FILTER doc._arango_cti_processor_note == "cve-cpe"
            AND doc._is_ref == true
            AND doc._is_latest == true
            RETURN doc
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [21], f"Expected 21 documents, but found {result_count}.")

# expecting to see two old _is_ref SROs for indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6
# had 2 SROs which creted 3 is_ref SROs in 6.0 that were updated in this 6.1 test.

    def test_02_count_is_ref_false(self):
        query = """
            FOR doc IN nvd_cve_edge_collection
                FILTER doc._arango_cti_processor_note == "cve-cpe"
                AND doc._is_ref == true
                AND doc._is_latest == false
                SORT doc.source_ref
                RETURN [{
                    "source_ref": doc.source_ref,
                    "target_ref": doc.target_ref,
                    "relationship_type": doc.relationship_type
        }]
        """
        result_count = self.run_query(query)
        expected_ids = [
          [
            {
              "source_ref": "relationship--d177fcc4-6991-5d5f-8885-7c27f374fce5",
              "target_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
              "relationship_type": "created-by"
            }
          ],
          [
            {
              "source_ref": "relationship--d177fcc4-6991-5d5f-8885-7c27f374fce5",
              "target_ref": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
              "relationship_type": "object-marking"
            }
          ],
          [
            {
              "source_ref": "relationship--d177fcc4-6991-5d5f-8885-7c27f374fce5",
              "target_ref": "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
              "relationship_type": "object-marking"
            }
          ],
          [
            {
              "source_ref": "relationship--f77ec4f3-f855-5dfd-9a4c-81b9124f15ac",
              "target_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
              "relationship_type": "created-by"
            }
          ],
          [
            {
              "source_ref": "relationship--f77ec4f3-f855-5dfd-9a4c-81b9124f15ac",
              "target_ref": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
              "relationship_type": "object-marking"
            }
          ],
          [
            {
              "source_ref": "relationship--f77ec4f3-f855-5dfd-9a4c-81b9124f15ac",
              "target_ref": "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
              "relationship_type": "object-marking"
            }
          ]
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
