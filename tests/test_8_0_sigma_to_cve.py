import os
import subprocess
import unittest
from arango import ArangoClient
from dotenv import load_dotenv
from stix2arango.stix2arango import Stix2Arango

from .upload import make_uploads

# Load environment variables
load_dotenv()

ARANGODB_USERNAME = os.getenv("ARANGODB_USERNAME")
ARANGODB_PASSWORD = os.getenv("ARANGODB_PASSWORD")
ARANGODB_HOST_URL = os.getenv("ARANGODB_HOST_URL")

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
            ("sigma_rules", "tests/files/sigma-rules-with-cves.json"),
            ("nvd_cve", "tests/files/condensed_cve_bundle.json"),
        ], database="arango_cti_processor_standard_tests", delete_db=True)
        # Run the arango_cti_processor.py script
        subprocess.run([
            "python3", "arango_cti_processor.py",
            "--database", "arango_cti_processor_standard_tests_database",
            "--relationship", "sigma-cve",
            "--stix2arango_note", "test08",
            "--ignore_embedded_relationships", "false"
        ], check=True)
        
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
            RETURN [doc]
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [15546], f"Expected 15546 documents, but found {result_count}.")


# test 3 Expecting 4 results (see test-data-research.md for info as to why).
# `indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1`
# links to `cve.2022.26134` (`vulnerability--b4fd2041-12ff-5a64-9c00-51ba39b29fe4`) and `cve.2021.26084` (`vulnerability--ff040ea3-f2d9-5d38-80ae-065a2db41e64`)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1+nvd_cve_vertex_collection/vulnerability--b4fd2041-12ff-5a64-9c00-51ba39b29fe4` = `relationship--71b515ec-a8bc-5b92-a732-8f2f7cfea05f`
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1+nvd_cve_vertex_collection/vulnerability--ff040ea3-f2d9-5d38-80ae-065a2db41e64` = `relationship--5c27d6ba-8cfc-5d1e-89a8-afc07bf27fb1`
# indicator--4c5cfb71-e0ef-58a6-8307-302f27038700
# links to cve.2023.22518 (vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--4c5cfb71-e0ef-58a6-8307-302f27038700+nvd_cve_vertex_collection/vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6` = `relationship--4e9ae0ed-f421-5a2e-acdb-f6146ee34c95`
# indicator--57ddd7ed-0a84-57ad-8fc0-dd892346ec32
# links to cve.2023.43621 (vulnerability--570304ae-02cf-542b-ab7a-77e7ada2f48e)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--57ddd7ed-0a84-57ad-8fc0-dd892346ec32+nvd_cve_vertex_collection/vulnerability--570304ae-02cf-542b-ab7a-77e7ada2f48e` = `relationship--d08f9a4d-1eed-562e-ae7c-0aecbfacf5ea`


    def test_03_check_generated_relationships(self):
        query = """
          FOR doc IN sigma_rules_edge_collection
              FILTER doc.relationship_type == "detects"
              RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "relationship--71b515ec-a8bc-5b92-a732-8f2f7cfea05f",
            "relationship--5c27d6ba-8cfc-5d1e-89a8-afc07bf27fb1",
            "relationship--4e9ae0ed-f421-5a2e-acdb-f6146ee34c95",
            "relationship--d08f9a4d-1eed-562e-ae7c-0aecbfacf5ea"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()