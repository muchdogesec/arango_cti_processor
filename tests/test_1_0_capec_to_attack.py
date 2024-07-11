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

# test 2 checks all objects generated correctly

def test_02_arango_cti_processor_note():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_capec_edge_collection
      FILTER doc._arango_cti_processor_note == "capec-attack"
        RETURN doc
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [338], f"Expected 338 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_02_arango_cti_processor_note()

# checks the corret number of objects are generated, and that they are assigned the correct properties by the script

def test_03_correct_object_properties():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_capec_edge_collection
        FILTER doc.type == "relationship"
        AND doc.relationship_type == "technique"
        AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
        AND doc.object_marking_refs == [
          "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
          "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
        ]
        AND doc._arango_cti_processor_note == "capec-attack"
        RETURN doc
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [338], f"Expected 338 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_03_correct_object_properties()

# test 4 checks [CAPEC-695](https://github.com/mitre/cti/blob/master/capec/2.1/attack-pattern/attack-pattern--e3dd79e7-307b-42dd-9e22-d0345c0ec001.json) -> T1195.001

def test_04_correct_relationship_capec695():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        FOR doc IN mitre_capec_edge_collection
          FILTER doc._is_latest == true
          AND doc._arango_cti_processor_note == "capec-attack"
          AND doc.source_ref == "attack-pattern--e3dd79e7-307b-42dd-9e22-d0345c0ec001"
          RETURN doc.target_ref
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    expected_ids = [
        "attack-pattern--191cc6af-1bb2-4344-ab5f-28e496638720"
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")

test_04_correct_relationship_capec695()

# test 5 is extension of test 4 to check id generation: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` value: `technique+mitre_capec_vertex_collection/attack-pattern--e3dd79e7-307b-42dd-9e22-d0345c0ec001+mitre_attack_enterprise_vertex_collection/attack-pattern--191cc6af-1bb2-4344-ab5f-28e496638720` = 34d58beb-5d4c-5899-b3aa-2a0d5995e82d

def test_05_relationship_id_generation695():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        FOR doc IN mitre_capec_edge_collection
          FILTER doc._is_latest == true
          AND doc._arango_cti_processor_note == "capec-attack"
          AND doc.source_ref == "attack-pattern--e3dd79e7-307b-42dd-9e22-d0345c0ec001"
          RETURN doc.id
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    expected_ids = [
        "relationship--34d58beb-5d4c-5899-b3aa-2a0d5995e82d"
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")

test_05_relationship_id_generation695()

# test 6 checks [CAPEC-233](https://github.com/mitre/cti/blob/master/capec/2.1/attack-pattern/attack-pattern--c05fff04-b965-4a11-9c18-379dac31969f.json) -> T1548

def test_06_correct_relationship_capec233():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        FOR doc IN mitre_capec_edge_collection
          FILTER doc._is_latest == true
          AND doc._arango_cti_processor_note == "capec-attack"
          AND doc.source_ref == "attack-pattern--c05fff04-b965-4a11-9c18-379dac31969f"
          RETURN doc.target_ref
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    expected_ids = [
        "attack-pattern--67720091-eee3-4d2d-ae16-8264567f6f5b"
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")

test_06_correct_relationship_capec233()

# test 7 is extension of test 6 to check id generation: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--c05fff04-b965-4a11-9c18-379dac31969f+mitre_attack_enterprise_vertex_collection/attack-pattern--67720091-eee3-4d2d-ae16-8264567f6f5b` = bc0d764e-f1ba-55ff-b871-7735ec140789

def test_07_relationship_id_generation233():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        FOR doc IN mitre_capec_edge_collection
          FILTER doc._is_latest == true
          AND doc._arango_cti_processor_note == "capec-attack"
          AND doc.source_ref == "attack-pattern--c05fff04-b965-4a11-9c18-379dac31969f"
          AND doc.id == ""
          RETURN doc.id
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    expected_ids = [
        "relationship--bc0d764e-f1ba-55ff-b871-7735ec140789"
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")

test_07_relationship_id_generation233()

# test 8 checks [CAPEC-13](https://github.com/mitre/cti/blob/master/capec/2.1/attack-pattern/attack-pattern--f190e1b3-e8d6-4aef-817c-b3e7782e2aed.json -> T1562.003, T1574.006, T1574.007

def test_08_correct_relationship_capec13():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        FOR doc IN mitre_capec_edge_collection
          FILTER doc._is_latest == true
          AND doc._arango_cti_processor_note == "capec-attack"
          AND doc.source_ref == "attack-pattern--f190e1b3-e8d6-4aef-817c-b3e7782e2aed"
          RETURN doc.target_ref
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    expected_ids = [
        "attack-pattern--8f504411-cb96-4dac-a537-8d2bb7679c59", # T1562.003
        "attack-pattern--633a100c-b2c9-41bf-9be5-905c1b16c825", # T1574.006
        "attack-pattern--0c2d00da-7742-49e7-9928-4514e5075d32" # T1574.007
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")

test_08_correct_relationship_capec13()

# test 9 is extension of test 8 to check id generation:
# object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--f190e1b3-e8d6-4aef-817c-b3e7782e2aed+mitre_attack_enterprise_vertex_collection/attack-pattern--8f504411-cb96-4dac-a537-8d2bb7679c59` = c1100173-c259-52a1-926d-48919b067224
# object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--f190e1b3-e8d6-4aef-817c-b3e7782e2aed+mitre_attack_enterprise_vertex_collection/attack-pattern--633a100c-b2c9-41bf-9be5-905c1b16c825` = d66bcc7d-19c0-5c2c-a7f7-44b13d6af09c
# object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--f190e1b3-e8d6-4aef-817c-b3e7782e2aed+mitre_attack_enterprise_vertex_collection/attack-pattern--0c2d00da-7742-49e7-9928-4514e5075d32` = 23bd53cf-0f53-53e3-8ba1-92b4077bd460

def test_09_relationship_id_generation13():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        FOR doc IN mitre_capec_edge_collection
          FILTER doc._is_latest == true
          AND doc._arango_cti_processor_note == "capec-attack"
          AND doc.source_ref == "attack-pattern--f190e1b3-e8d6-4aef-817c-b3e7782e2aed"
          RETURN doc.id
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    expected_ids = [
        "relationship--c1100173-c259-52a1-926d-48919b067224", # T1562.003
        "relationship--d66bcc7d-19c0-5c2c-a7f7-44b13d6af09c", # T1574.006
        "relationship--23bd53cf-0f53-53e3-8ba1-92b4077bd460" # T1574.007
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")

test_09_relationship_id_generation13()

def test_10_check_no_updates():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        RETURN LENGTH(
          FOR doc IN mitre_capec_edge_collection
            FILTER doc._is_latest == false
            AND doc._arango_cti_processor_note == "capec-attack"
            RETURN doc
        )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [0], f"Expected 338 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_10_check_no_updates()