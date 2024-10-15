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
TEST_MODE = "sigma-cve"
STIX2ARANGO_NOTE = __name__.split('.')[-1]
IGNORE_EMBEDDED_RELATIONSHIPS = "false"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("sigma_rules", "tests/files/sigma-rules-with-cves.json"),
                ("nvd_cve", "tests/files/condensed_cve_bundle.json"),
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
          FOR doc IN sigma_rules_vertex_collection
            FILTER doc._arango_cti_processor_note == "automatically imported object at script runtime"
            RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

# there are 4 references to cves inside the sigma rules (2 with 1 ref, and 1 with 2 refs)
    def test_02_check_generated_relationships(self):
        query = """
        RETURN LENGTH(
          FOR doc IN sigma_rules_edge_collection
            FILTER doc._is_latest == true
            AND doc.relationship_type == "detects"
            AND doc._arango_cti_processor_note == "sigma-cve"
            AND doc.object_marking_refs == [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
            ]
            AND doc._is_ref == false
            RETURN [doc]
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [4], f"Expected 4 documents, but found {result_count}.")

# test 3 Expecting 4 results (see test-data-research.md for info as to why).

# indicator--c6e28172-84af-594d-b09a-565a10121fe0
# links to `cve.2022.26134` (`vulnerability--b4fd2041-12ff-5a64-9c00-51ba39b29fe4`) and `cve.2021.26084` (`vulnerability--ff040ea3-f2d9-5d38-80ae-065a2db41e64`)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--c6e28172-84af-594d-b09a-565a10121fe0+nvd_cve_vertex_collection/vulnerability--b4fd2041-12ff-5a64-9c00-51ba39b29fe4` = ec3549ba-dcc4-5705-a771-65a166a12bf7
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--c6e28172-84af-594d-b09a-565a10121fe0+nvd_cve_vertex_collection/vulnerability--ff040ea3-f2d9-5d38-80ae-065a2db41e64` = 674df306-4008-5306-82cb-0545630e93df

# indicator--60b9f6b7-eb2b-50c8-83e3-fd3f90b0a3b5
# links to cve.2023.22518 (vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--60b9f6b7-eb2b-50c8-83e3-fd3f90b0a3b5+nvd_cve_vertex_collection/vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6` = 72189b73-5547-500c-85ea-f9287eac93f2

# indicator--0e2e33f3-78c4-52da-8323-4fb13421fc65
# links to cve.2023.43621 (vulnerability--570304ae-02cf-542b-ab7a-77e7ada2f48e)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--0e2e33f3-78c4-52da-8323-4fb13421fc65+nvd_cve_vertex_collection/vulnerability--570304ae-02cf-542b-ab7a-77e7ada2f48e` = 1f98535e-722a-5249-8535-6147bb36a048


    def test_03_check_generated_relationships(self):
        query = """
          FOR doc IN sigma_rules_edge_collection
              FILTER doc.relationship_type == "detects"
              AND doc._is_ref == false
              SORT doc.id ASC
              RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
          "relationship--1f98535e-722a-5249-8535-6147bb36a048",
          "relationship--674df306-4008-5306-82cb-0545630e93df",
          "relationship--72189b73-5547-500c-85ea-f9287eac93f2",
          "relationship--ec3549ba-dcc4-5705-a771-65a166a12bf7"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    def test_04_check_object_description_properties(self):
        query = """
            FOR doc IN sigma_rules_edge_collection
                FILTER doc._arango_cti_processor_note == "sigma-cve"
                AND doc.id == "relationship--72189b73-5547-500c-85ea-f9287eac93f2"
                AND doc._is_ref == false
                RETURN doc.description
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
          "CVE-2023-22518 Exploitation Attempt - Suspicious Confluence Child Process (Windows) detects CVE-2023-22518"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")


if __name__ == '__main__':
    unittest.main()