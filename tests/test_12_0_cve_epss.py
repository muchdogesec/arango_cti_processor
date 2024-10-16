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
        make_uploads([
                ("nvd_cve", "tests/files/epss-cves.json"),
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


    # test 2 Should return the 2 for the CVEs with EPSS, and 1 for the EPSS added by ACTIP
    def test_02_arango_cti_processor_note(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_vertex_collection
          FILTER doc.type == "note"
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [3], f"Expected 3 documents, but found {result_count}.")

    # test 3 Should return the 2 for the CVEs with EPSS already (created by cve2stix)
    def test_03_arango_cti_processor_note(self):
        query = """
        RETURN COUNT(  
          FOR doc IN nvd_cve_vertex_collection
          FILTER doc.type == "note"
          AND doc.created_by_ref == "identity--562918ee-d5da-5579-b6a1-fae50cc6bad3"
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [2], f"Expected 2 documents, but found {result_count}.")

    # test 4 Should return the 1 for the CVE without EPSS already (created by ACTIP)
    def test_04_arango_cti_processor_note(self):
        query = """
        RETURN COUNT(  
          FOR doc IN nvd_cve_vertex_collection
          FILTER doc.type == "note"
          AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [1], f"Expected 1 documents, but found {result_count}.")

    # test 5 check id for vulnerability--f670ff06-f9cc-5434-bab3-61d6fdb63e93
    def test_05_arango_cti_processor_note(self):
        query = """
        FOR doc IN nvd_cve_vertex_collection
            FILTER doc.type == "note"
            AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
            RETURN [{
                "id": doc.id,
                "created_by_ref": doc.created_by_ref,
                "content": doc.content,
                "object_refs": doc.object_refs,
                "external_references": doc.external_references,
                "object_marking_refs": doc.object_marking_refs,
                "_arango_cti_processor_note": doc._arango_cti_processor_note
            }]
        """
        result_count = self.run_query(query)
        expected_ids = [
          [
            {
              "id": "note--f670ff06-f9cc-5434-bab3-61d6fdb63e93",
              "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
              "content": "EPSS Score for CVE-2024-1848",
              "object_refs": [
                "vulnerability--f670ff06-f9cc-5434-bab3-61d6fdb63e93"
              ],
              "external_references": [
                {
                  "source_name": "cve",
                  "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1848",
                  "external_id": "CVE-2024-1848"
                }
              ],
              "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
              ],
              "_arango_cti_processor_note": "cve-epss"
            }
          ]
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")
    # check the Note object has the correct structure

    # here we expect 2 results per note (the one imported for 2024-10-08, and the one added by the script for NOW)
    def test_06_check_count_of_dates(self):
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
          },
          {
            "id": "note--f670ff06-f9cc-5434-bab3-61d6fdb63e93",
            "date_count": 1
          }
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
