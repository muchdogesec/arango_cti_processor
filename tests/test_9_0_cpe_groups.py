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
            "--relationship", "cpe-groups",
            "--stix2arango_note", "test09",
            "--ignore_embedded_relationships", "false"
        ], check=True)
        
        cls.db = client.db('arango_cti_processor_standard_tests_database', username=ARANGODB_USERNAME, password=ARANGODB_PASSWORD)

    def run_query(self, query):
        cursor = self.db.aql.execute(query)
        return [count for count in cursor]

    # should still return 2 objects b/c these never update
    def test_01_auto_imported_objects(self):
        query = """
          FOR doc IN nvd_cpe_vertex_collection
            FILTER doc._arango_cti_processor_note == "automatically imported object at script runtime"
            RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 2 Should return 202 results, as 202 unique software objects in dataset
    def test_02_check_product_groupings(self):
        query = """
        RETURN LENGTH(
          FOR doc IN nvd_cpe_vertex_collection
            FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
            AND doc._arango_cti_processor_note == "cpe-groups"
            AND doc.name LIKE "Product:%"
            AND doc.object_marking_refs == [
              "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
              "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
            ]
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [202], f"Expected 202 documents, but found {result_count}.")

    # test 3 Will return 9 results for IDs of software objects where product = chrome. 
    def test_03_check_product_groupings_chrome(self):
        query = """
        RETURN LENGTH(
          FOR doc IN nvd_cpe_vertex_collection
              FILTER doc._stix2arango_note != "automatically imported on collection creation"
              AND doc.type == "software"
              LET cpe_parts = SPLIT(doc.cpe, ":")
              LET product = cpe_parts[4]
              FILTER product == "chrome"
              RETURN doc.id
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [9], f"Expected 9 documents, but found {result_count}.")

# test 4 check the id For the product grouping object for this software (chrome) the ID will be: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `chrome` = `grouping--9a385c8c-608f-5abe-8e93-9af359a02397`

    def test_04_check_product_groupings_chrome_id(self):
        query = """
        RETURN LENGTH(
          FOR doc IN nvd_cpe_vertex_collection
            FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
            AND doc._arango_cti_processor_note == "cpe-groups"
            AND doc.id == "grouping--9a385c8c-608f-5abe-8e93-9af359a02397"
            RETURN [doc]
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [1], f"Expected 1 documents, but found {result_count}.")

# test 5 The object `object_refs` should have 9 `software` objects representing the 9 software versions of chrome that exist.
    def test_05_check_product_groupings_chrome_object_refs(self):
        query = """
          FOR doc IN nvd_cpe_vertex_collection
            FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
            AND doc._arango_cti_processor_note == "cpe-groups"
            AND doc.id == "grouping--9a385c8c-608f-5abe-8e93-9af359a02397"
            RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")




