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
                ("nvd_cve", "tests/files/condensed_cve_bundle.json"),
                ("nvd_cpe", "tests/files/condensed_cpe_bundle.json"),
            ], database="arango_cti_processor_standard_tests", delete_db=True, 
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

# condensed_cve_bundle.json generates 6 SROs, inside these SROs are a total of 18 embedded relationships (each has 1 created_by_ref and 2 object_marking_refs)

    def test_01_count_is_ref(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_edge_collection
            FILTER doc._arango_cti_processor_note == "cve-cpe"
            AND doc._is_ref == true
            RETURN doc
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [18], f"Expected 18 documents, but found {result_count}.")

# check id of one of the generate objects
# `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` created-by+nvd_cve_edge_collection/relationship--d177fcc4-6991-5d5f-8885-7c27f374fce5+nvd_cve_vertex_collection/identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3 = 761f7bbf-9403-5d52-a676-20721f1f5b48

    def test_01_count_is_ref_object1(self):
        query = """
          FOR doc IN nvd_cve_edge_collection
            FILTER doc._arango_cti_processor_note == "cve-cpe"
            AND doc.id == "relationship--761f7bbf-9403-5d52-a676-20721f1f5b48"
            RETURN [{
                "created_by_ref": doc.created_by_ref,
                "object_marking_refs": doc.object_marking_refs,
                "_stix2arango_note": doc._stix2arango_note,
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
                  "_stix2arango_note": "test_10_0_ignore_embedded_relationships_f",
                  "_arango_cti_processor_note": "cve-cpe",
                  "_is_latest": True
                }
              ]
            ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()