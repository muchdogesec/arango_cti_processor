import os
import subprocess
from arango import ArangoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

ARANGO_USERNAME = os.getenv("ARANGODB_USERNAME")
ARANGO_PASSWORD = os.getenv("ARANGODB_PASSWORD")
ARANGODB_HOST_URL = os.getenv("ARANGODB_HOST_URL", "localhost")

client = ArangoClient(hosts=f"{ARANGO_HOST_URL}:{ARANGO_PORT}")

# Run the import script
subprocess.run([
    "python3", "arango_cti_processor.py",
    "--database", "arango_cti_processor_standard_tests_database",
    "--relationship", "capec-attack",
    "--stix2arango_note", "test01",
    "--ignore_embedded_relationships", "false"
], check=True)

print('Script executed successfully.')

# Test 1 still expect still on 2 results (as no versioned objects should be created for auto imports -- b/c md5's are the same)

def test_01_auto_imported_objects():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
      FOR doc IN mitre_capec_vertex_collection
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

test_01_auto_imported_objects()

# test 2 CAPEC-158 attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a update check

def test_02_update_capec158():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        RETURN COUNT(
            FOR doc IN mitre_capec_vertex_collection
              FILTER doc.id == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
              RETURN doc
        )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [2], f"Expected 2 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_02_update_capec158()

# test 3 CAPEC-158 attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a old version

def test_03_update_capec158_old_version():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        RETURN COUNT(
            FOR doc IN mitre_capec_vertex_collection
              FILTER doc.id == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
              AND doc._is_latest == false
              RETURN doc
        )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [1], f"Expected 1 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_03_update_capec158_old_version()

# test 4 check relationships for old version of CAPEC-158. Should return 4 results, because old version of `attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a` had 2 ATT&CK references (but each one resolves to 1 attack-pattern, and 1 course-of-action).

def test_04_update_capec158_old_version_relationships():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        RETURN COUNT(
            FOR doc IN mitre_capec_edge_collection
              FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
              AND doc._is_latest == false
              AND doc._arango_cti_processor_note == "capec-attack"
              RETURN doc
        )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [4], f"Expected 4 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_04_update_capec158_old_version_relationships()

# test 5 Should return 3 results, because new version of `attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a` has 3 ATT&CK references -- the new one with one link to an attack-pattern

def test_05_update_capec158_new_version_relationships():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        RETURN COUNT(
            FOR doc IN mitre_capec_edge_collection
              FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
              AND doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-attack"
              RETURN doc
        )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [5], f"Expected 5 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_05_update_capec158_new_version_relationships()

# test 6 test the relationship ids are correct

def test_06_update_capec158_check_relationship_ids():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
      FOR doc IN mitre_capec_edge_collection
        FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
        AND doc._is_latest == true
        AND doc._arango_cti_processor_note == "capec-attack"
            RETURN doc
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    expected_ids = [
        ""
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")

def test_06_update_capec158_check_relationship_ids()

# test 7 this is the new CAPEC-999 object

def test_07_new_capec999():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
        FOR doc IN mitre_capec_edge_collection
          FILTER doc.id == "attack-pattern--39b37ebd-276c-48e7-b152-d94a29599f4b"
          AND doc._is_latest == true
          AND doc._arango_cti_processor_note == "capec-attack"
          RETURN doc
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [1], f"Expected 1 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_07_new_capec999()

# test 8 this is the new CAPEC-999 object, so should be no old objects

def test_08_new_capec999_update():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
        FOR doc IN mitre_capec_edge_collection
          FILTER doc.id == "attack-pattern--39b37ebd-276c-48e7-b152-d94a29599f4b"
          AND doc._is_latest == false
          AND doc._arango_cti_processor_note == "capec-attack"
          RETURN doc
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [0], f"Expected 0 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_08_new_capec999_update()