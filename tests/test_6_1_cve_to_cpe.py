import os
import subprocess
from arango import ArangoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

ARANGO_USERNAME = os.getenv("ARANGODB_USERNAME")
ARANGO_PASSWORD = os.getenv("ARANGODB_PASSWORD")
ARANGO_HOST = os.getenv("ARANGODB_HOST", "localhost")
ARANGO_PORT = os.getenv("ARANGODB_PORT", "8529")

client = ArangoClient(hosts=f"http://{ARANGO_HOST}:{ARANGO_PORT}")

# Run the import script
subprocess.run([
    "python3", "arango_cti_processor.py",
    "--database", "arango_cti_processor_standard_tests_database",
    "--relationship", "cve-cpe",
    "--stix2arango_note", "test06",
    "--ignore_embedded_relationships", "false"
], check=True)

print('Script executed successfully.')

def test_01_auto_imported_objects():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
      FOR doc IN nvd_cve_vertex_collection
        FILTER doc._arango_cti_processor_note == "automatically imported object at script runtime"
        RETURN doc.id
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    expected_ids = [
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
        "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")

# Should return 2 results, the new and old version of `indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6` (CVE-2023-22518)

def test_02_test_update_to_indicator():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN nvd_cve_vertex_collection
        FILTER doc.id == "indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
          RETURN doc
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [2], f"Expected 2 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_02_test_update_to_indicator()

# test 3 Should return 3 results, as now has 3 CPEs in Pattern

def test_03_test_relationships_to_cpes_new():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN nvd_cve_edge_collection
          FILTER doc.source_ref == "indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
          AND doc.relationship_type == "pattern-contains"
          AND doc._is_latest == true
          RETURN doc
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [3], f"Expected 3 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_03_test_relationships_to_cpes_new()

# Should return 2 results, as the original indicator (in 6.0) before update has 2 CPEs in pattern.

def test_04_test_relationships_to_cpes_old():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN nvd_cve_edge_collection
          FILTER doc.source_ref == "indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
          AND doc.relationship_type == "pattern-contains"
          AND doc._is_latest == false
          RETURN doc
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [3], f"Expected 3 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_04_test_relationships_to_cpes_old()