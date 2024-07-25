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

# test 2 Will return 13 results (2 new objects, from 11 in test 9.1)

    def test_02_check_vendor_groupings_google(self):
        query = """
        RETURN LENGTH(
          FOR doc IN nvd_cpe_vertex_collection
              FILTER doc._stix2arango_note != "automatically imported on collection creation"
              AND doc.type == "software"
              LET cpe_parts = SPLIT(doc.cpe, ":")
              LET vendor = cpe_parts[3]
              LET product = cpe_parts[4]
              FILTER vendor == "google"
              RETURN product
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [13], f"Expected 11 documents, but found {result_count}.")

# test 3 Lets start by looking at the brand new product (`new`). This search should return one result for the grouping object that should have been created for it. We expect it to have the ID: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `new` = `grouping--5a242cbb-1bf3-596e-abc9-18747e6c5261`

    def test_03_check_new_grouping(self):
        query = """
        RETURN LENGTH(
          FOR doc IN nvd_cpe_vertex_collection
          FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
            AND doc._arango_cti_processor_note == "cpe-groups"
            AND doc.id == grouping--5a242cbb-1bf3-596e-abc9-18747e6c5261
            AND doc.type == "grouping"
            AND doc.name == "Product: new"
            RETURN [doc]
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [1], f"Expected 1 documents, but found {result_count}.")

# test 4 should be same result as 8.0 (this is the old object)

    def test_04_check_vendor_groupings_google_old(self):
        query = """
        FOR doc IN nvd_cpe_vertex_collection
            FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
            AND doc._arango_cti_processor_note == "cpe-groups"
            AND doc._is_latest == false
            AND doc.id == "grouping--1e39385c-96f3-5511-8601-1b58c86ceb08"
            AND doc.object_marking_refs == [
              "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
              "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
            ]
            RETURN doc.object_refs
        """
        result_count = self.run_query(query)
        expected_ids = [
            "grouping--c0f2c5c6-3c85-54c5-8f93-97c0d6c3b7c0",
            "grouping--1e840f28-abb5-510a-9150-7d98a6b48413",
            "grouping--9a385c8c-608f-5abe-8e93-9af359a02397"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

# test 5 count in new object should be 4, b/c one new object added. Same search, but this time only showing latest version which should have 4 object_refs including `grouping--5a242cbb-1bf3-596e-abc9-18747e6c5261` for product `new` added in update.

    def test_05_check_vendor_groupings_google_new_self):
        query = """
        FOR doc IN nvd_cpe_vertex_collection
            FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
            AND doc._arango_cti_processor_note == "cpe-groups"
            AND doc._is_latest == false
            AND doc.id == "grouping--1e39385c-96f3-5511-8601-1b58c86ceb08"
            AND doc.object_marking_refs == [
              "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
              "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
            ]
            RETURN doc.object_refs
        """
        result_count = self.run_query(query)
        expected_ids = [
            "grouping--c0f2c5c6-3c85-54c5-8f93-97c0d6c3b7c0",
            "grouping--1e840f28-abb5-510a-9150-7d98a6b48413",
            "grouping--9a385c8c-608f-5abe-8e93-9af359a02397",
            "grouping--5a242cbb-1bf3-596e-abc9-18747e6c5261"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 6 Will return 10 results for IDs of software objects where product = chrome. (was 9 in 9.0, 1 added in 9.1)
    def test_06_check_product_groupings_chrome(self):
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
        self.assertEqual(result_count, [10], f"Expected 10 documents, but found {result_count}.")

# test 7 The object `object_refs` should have 10 `software` objects. Was 9 in 9.0, 1 added in 9.1
    def test_07_check_product_groupings_chrome_object_refs(self):
        query = """
          FOR doc IN nvd_cpe_vertex_collection
            FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
            AND doc._arango_cti_processor_note == "cpe-groups"
            AND doc.id == "grouping--9a385c8c-608f-5abe-8e93-9af359a02397"
            RETURN doc.object_refs
        """
        result_count = self.run_query(query)
        expected_ids = [
            "software--",
            "software--",
            "software--",
            "software--",
            "software--",
            "software--",
            "software--",
            "software--",
            "software--",
            "software--"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")


if __name__ == '__main__':
    unittest.main()