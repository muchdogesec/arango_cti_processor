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
    "--relationship", "capec-attack",
    "--stix2arango_note", "test01",
    "--ignore_embedded_relationships", "false"
], check=True)

print('Script executed successfully.')

# test 1 Should return 4 objects, the newest version, and 3 old ones.

def test_01_updated_capec158():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_capec_vertex_collection
          FILTER doc.id == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
          RETURN [doc]
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [4], f"Expected 4 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_01_updated_CAPEC158()

# test 2 Should return 15 results. oldest version (1.0) of CAPEC158 had 4 ATT&CK references, old version 1.1 had 5 ATT&CK references, old version 1.2 had 6

def test_02_updated_capec158_old_relationships():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_capec_edge_collection
          FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
          AND doc._is_latest == false
          AND doc._arango_cti_processor_note == "capec-attack"
          RETURN [doc]
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [15], f"Expected 15 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_02_updated_capec158_old_relationships()

# test 3 Should return 4 results because the new object has both T1040 (1 coa, 1 attack pattern) and T1111 (1 coa, 1 attack pattern)

def test_03_updated_capec158_new_relationships():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_capec_edge_collection
          FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
          AND doc._is_latest == true
          AND doc._arango_cti_processor_note == "capec-attack"
          RETURN [doc]
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [4], f"Expected 4 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_03_updated_capec158_new_relationships()

# test 4 is extensions of test 3 but checks target ids

def test_04_updated_capec158_new_relationships_check_ids():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_capec_edge_collection
          FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
          AND doc._is_latest == true
          AND doc._arango_cti_processor_note == "capec-attack"
          RETURN doc.target_ref
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    expected_ids = [
        "course-of-action--46b7ef91-4e1d-43c5-a2eb-00fa9444f6f4", # Enterprise T1040
        "attack-pattern--3257eb21-f9a7-4430-8de1-d8b6e288f529", # Enterprise T1040
        "course-of-action--e8d22ec6-2236-48de-954b-974d17492782", # Enterprise T1111
        "attack-pattern--dd43c543-bb85-4a6f-aa6e-160d90d06a49", # Enterprise T1111
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")

test_04_updated_capec158_new_relationships_check_ids()

# test 5 check t1650 (attack-pattern--d21bb61f-08ad-4dc1-b001-81ca6cb79954). this only exists in updates 1.1. and 1.2.

def test_05_updated_capec158_new_relationships_t1650():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_capec_edge_collection
          FILTER doc.target_ref == "attack-pattern--d21bb61f-08ad-4dc1-b001-81ca6cb79954"
          AND doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
          AND doc._is_latest == false
          AND doc._arango_cti_processor_note == "capec-attack"
          RETURN doc
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [2], f"Expected 2 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_05_updated_capec158_new_relationships_t1650()

# test 6 is extension of test 5, but checks there is no latest version

def test_06_updated_capec158_new_relationships_t1650_new():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_capec_edge_collection
          FILTER doc.target_ref == "attack-pattern--d21bb61f-08ad-4dc1-b001-81ca6cb79954"
          AND doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
          AND doc._is_latest == true
          AND doc._arango_cti_processor_note == "capec-attack"
          RETURN doc
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [0], f"Expected 0 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_06_updated_capec158_new_relationships_t1650_new()