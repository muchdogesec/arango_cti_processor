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
            "--relationship", "sigma-attack",
            "--stix2arango_note", "test07",
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

    # test 2 Should return 2 results, the new and old object.
    def test_02_updated_object(self):
        query = """
        RETURN LENGTH(
          FOR doc IN sigma_rules_vertex_collection
              FILTER doc.id == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [2], f"Expected 2 documents, but found {result_count}.")

    # test 3 check old relationship objects generated for indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1 in 7.0
    def test_03_check_old_objects_for_update(self):
        query = """
        RETURN LENGTH(
          FOR doc IN sigma_rules_edge_collection
              FILTER doc._is_latest == false
              AND doc.relationship_type == "detects"
              AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
              AND doc.object_marking_refs == [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
              ]
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [5], f"Expected 5 documents, but found {result_count}.")

    # test 4 check new relationship objects generated for indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1
    def test_04_check_new_objects_for_update(self):
        query = """
        RETURN LENGTH(
          FOR doc IN sigma_rules_edge_collection
          FILTER doc._is_latest == true
          AND doc.relationship_type == "detects"
          AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
          AND doc.object_marking_refs == [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
          ]
          RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [6], f"Expected 6 documents, but found {result_count}.")

# test 5, same as 4 but checks ids
#* attack.initial_access
#  * x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca (enterprise)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1+mitre_attack_enterprise_vertex_collection/x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca` = `relationship--c0d42d62-05b3-5472-83d8-dea67a0b39eb`
#  * x-mitre-tactic--69da72d2-f550-41c5-ab9e-e8255707f28a (ics)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1+mitre_attack_ics_vertex_collection/x-mitre-tactic--69da72d2-f550-41c5-ab9e-e8255707f28a` = `relationship--8e940387-b8d6-5816-a168-3a724d486775`
#  * x-mitre-tactic--10fa8d8d-1b04-4176-917e-738724239981 (mobile)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1+mitre_attack_mobile_vertex_collection/x-mitre-tactic--10fa8d8d-1b04-4176-917e-738724239981` = `relationship--5f4f0675-2c02-5202-9927-9c07ea32974a`
#* attack.t1190
#  * course-of-action--65da1eb6-d35d-4853-b280-98a76c0aef53 (enterprise)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1+mitre_attack_enterprise_vertex_collection/course-of-action--65da1eb6-d35d-4853-b280-98a76c0aef53` = `relationship--0c085dac-83e0-5029-9ba6-b8757c868973`
#  * attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c (enterprise)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1+mitre_attack_enterprise_vertex_collection/attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c` = `relationship--6a739749-5df8-5720-b68e-114e9fbf6845`
#* attack.t1543.003
#  * attack-pattern--2959d63f-73fd-46a1-abd2-109d7dcede32 (enterprise)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1+mitre_attack_enterprise_vertex_collection/attack-pattern--2959d63f-73fd-46a1-abd2-109d7dcede32` = `relationship--2978aedd-2f24-5991-9587-4a6f33a9eaec`

    def test_05_check_ids(self):
        query = """
          FOR doc IN sigma_rules_edge_collection
          FILTER doc._is_latest == true
          AND doc.relationship_type == "detects"
          AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
          AND doc.object_marking_refs == [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
          ]
          RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "relationship--c0d42d62-05b3-5472-83d8-dea67a0b39eb",
            "relationship--8e940387-b8d6-5816-a168-3a724d486775",
            "relationship--0c085dac-83e0-5029-9ba6-b8757c868973",
            "relationship--6a739749-5df8-5720-b68e-114e9fbf6845",
            "relationship--2978aedd-2f24-5991-9587-4a6f33a9eaec"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
