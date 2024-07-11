# Tests

## TEST 1.0 Validate CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

This test checks initial run of script on objects.

Delete any old data that might exist from old tests:

```shell
python3 tests/delete_all_databases.py
```

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 utilities/arango_cti_processor/insert_archive_attack_enterprise.py \
  --database arango_cti_processor_standard_tests \
  --ignore_embedded_relationships true \
  --versions 14_1 && \
python3 utilities/arango_cti_processor/insert_archive_attack_ics.py \
  --database arango_cti_processor_standard_tests \
  --ignore_embedded_relationships true \
  --versions 14_1 && \
python3 utilities/arango_cti_processor/insert_archive_attack_mobile.py \
  --database arango_cti_processor_standard_tests \
  --ignore_embedded_relationships true \
  --versions 14_1 && \
python3 utilities/arango_cti_processor/insert_archive_capec.py \
  --database arango_cti_processor_standard_tests \
  --ignore_embedded_relationships true \
  --versions 3_9
```

Run the test script;

```shell
python3 -m unittest tests/test_1_0_capec_to_attack.py
```

## TEST 1.1: Perform update to change CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

Note, test 1.0 must have been run for this test to work.

Here we provide an update to 2 objects in the CAPEC update bundle, 

* 1 is brand new CAPEC with 1 att&ck reference `attack-pattern--39b37ebd-276c-48e7-b152-d94a29599f4b` (CAPEC-999) to T1650
* 1 is an update to an existing CAPEC object (T1650 1 new att&ck reference is added) (2 previously existed T1040 and T1111) `attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a` (CAPEC-158) so now 3 attack objects.

Expected is that the new object is identified by the script and relationships generated.

For the updated objects, expected is that old SROs created by arango_cti_processor are marked as `_is_latest==false` (2 total) and 3 new objects (1 new, 2 existing recreated)

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 stix2arango.py \
  --file tests/files/arango_cti_processor/arango-cti-capec-attack-update-1.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_capec \
  --stix2arango_note v3.10 \
  --ignore_embedded_relationships true
```

Run the test script;

```shell
python3 -m unittest tests/test_1_1_capec_to_attack.py
```

## TEST 1.2: Perform ANOTHER update to change CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

Note, test 1.1 must have been run for this test to work.

Here we provide an update `attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a` for a second time, where 1 new att&ck reference is added (3 previously existed T1040, T1650, T1111, so 4 now with addition of T1574.010)

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 stix2arango.py \
  --file tests/files/arango_cti_processor/arango-cti-capec-attack-update-2.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_capec \
  --stix2arango_note v3.11 \
  --ignore_embedded_relationships true
```

Run the test script;

```shell
python3 -m unittest tests/test_1_2_capec_to_attack.py
```

### TEST 1.3 Perform ANOTHER update to change CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

Note, test 1.2 must have been run for this test to work.

This time we remove 2 of the ATT&CK references inside the CAPEC object (`attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a`), with 2 remaining T1040 and T1111. This is now the same as the original stix-capec-v3.9.json object

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 stix2arango.py \
  --file tests/files/arango_cti_processor/arango-cti-capec-attack-update-3.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_capec \
  --stix2arango_note v3.12 \
  --ignore_embedded_relationships true
```

Run the test script;

```shell
python3 -m unittest tests/test_1_3_capec_to_attack.py
```

### TEST 1.4 Perform ANOTHER update to change CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

Note, test 1.3 must have been run for this test to work.

This time we are adding ATT&CK references back to `attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a`. 

The doc now contains the same references as test 1.3 (4 in total): T1040, T1650, T1111, T1574.010

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 stix2arango.py \
  --file tests/files/arango_cti_processor/arango-cti-capec-attack-update-4.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_capec \
  --stix2arango_note v3.13 \
  --ignore_embedded_relationships true
```

Run the test script;

```shell
python3 -m unittest tests/test_1_4_capec_to_attack.py
```

## TEST 1.5 Perform ANOTHER update to change CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

Note, test 1.4 must have been run for this test to work.

This time we remove all of the ATT&CK references inside the CAPEC object (`attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a`).

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 stix2arango.py \
  --file tests/files/arango_cti_processor/arango-cti-capec-attack-update-5.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_capec \
  --stix2arango_note v3.14 \
  --ignore_embedded_relationships true
```

Run the test script;

```shell
python3 -m unittest tests/test_1_5_capec_to_attack.py
```

Should return 0 result, as no ATT&CK references exist in this CAPEC object now.

## TEST 2.0: Validate CAPEC Attack Pattern -> CWE Weakness relationship (`capec-cwe`)

Delete any old data from test 1.x for easier debugging:

```shell
python3 tests/delete_all_databases.py
```

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 utilities/arango_cti_processor/insert_archive_capec.py \
  --database arango_cti_processor_standard_tests \
  --ignore_embedded_relationships true \
  --versions 3_9 && \
python3 utilities/arango_cti_processor/insert_archive_cwe.py \
  --database arango_cti_processor_standard_tests \
  --ignore_embedded_relationships true \
  --versions 4_13
```

Run the test script;

```shell
python3 -m unittest tests/test_2_0_capec_to_cwe.py
```

## TEST 2.1: Add new CWE Weakness to CAPEC (`capec-cwe`)

In this file I update CAPEC-112 (`attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1`) with one new CWE; CWE-1004. It now has 4 CWE references.

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 stix2arango.py \
  --file tests/files/arango_cti_processor/arango-cti-capec-cwe-update-1.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_capec \
  --stix2arango_note v3.10 \
  --ignore_embedded_relationships true
```

Run the test script;

```shell
python3 -m unittest tests/test_2_1_capec_to_cwe.py
```



```sql
FOR doc IN mitre_capec_vertex_collection
  FILTER doc.id == "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"
  RETURN [doc]
```

Should return 2 objects, the new and old version.

```sql
FOR doc IN mitre_capec_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "exploits"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"
  AND doc._arango_cti_processor_note == "capec-cwe"
  RETURN [doc]
```

Should return 4 results, as 4 objects in latest version.

```sql
FOR doc IN mitre_capec_edge_collection
  FILTER doc._is_latest == false
  AND doc.relationship_type == "exploits"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"
  AND doc._arango_cti_processor_note == "capec-cwe"
  RETURN [doc]
```

Should return 3 results, as old object from 2.1 had 3 references.

```sql
FOR doc IN mitre_capec_edge_collection
  FILTER doc.relationship_type == "exploits"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"
  AND doc._arango_cti_processor_note == "capec-cwe"
  RETURN [doc]
```

Should return 7 results, both new and old objects.

### TEST 3.1: Validate CWE Weakness -> CAPEC Attack Pattern relationship (`cwe-capec`)

Delete any old data:

```shell
python3 design/mvp/test-helpers/remove-all-collections.py
```

Import required data:

```shell
python3 stix2arango.py  \
  --file backfill_data/mitre_cwe/cwe-bundle-4_13.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_cwe \
  --stix2arango_note v4.13 \
  --ignore_embedded_relationships true && \
python3 stix2arango.py  \
  --file backfill_data/mitre_capec/stix-capec-v3_9.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_capec \
  --stix2arango_note v3.9 \
  --ignore_embedded_relationships true
```

Run the script:

```shell
python3 arango_cti_processor.py \
  --relationship cwe-capec
```

```sql
RETURN LENGTH(
  FOR doc IN mitre_cwe_edge_collection
    FILTER doc._is_latest == true
    AND doc.relationship_type == "exploited-using"
    AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    AND doc.object_marking_refs == [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
    RETURN [doc]
)
```

Should return all the SROs generated by arango_cti_processor -- expected = 1212

To check objects are created as expected, you can pick a CWE object with CAPEC references and then check all the SROs for CAPECs are generated for it, as follows...

e.g. CWE-521 (weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5) which has links to 9 CAPEC IDs;

* CAPEC-112 (`attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1`)
* CAPEC-16 (`attack-pattern--a9dc4914-409a-4f71-80df-c5cc3923d112`)
* CAPEC-49 (`attack-pattern--8d88a81c-bde9-4fb3-acbe-901c783d6427`)
* CAPEC-55 (`attack-pattern--a390cb72-b4de-4750-ae05-be556c89f4be`)
* CAPEC-555 (`attack-pattern--06e8782a-87af-4863-b6b1-99e09edda3be`)
* CAPEC-561 (`attack-pattern--f2654def-b86d-4ddb-888f-de6b50a103a2`)
* CAPEC-565 (`attack-pattern--f724f0f3-20e6-450c-be4a-f373ea08834d`)
* CAPEC-70 (`attack-pattern--8c7bab16-5ecd-4778-9b04-c185bceed170`)
* CAPEC-509 (`attack-pattern--9197c7a2-6a03-40da-b2a6-df5f1d69e8fb`)

```sql
FOR doc IN mitre_cwe_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "exploited-using"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5"
  RETURN [doc]
```

Should therefore return 9 results.

```sql
FOR doc IN mitre_cwe_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "exploited-using"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5"
  AND doc.id IN [
    "relationship--08e771e1-43a8-5274-a40e-6e0c2a80a839",
    "relationship--cba7ab38-92a9-5a3e-b764-6c0eee7115f4",
    "relationship--3160ac44-e035-501c-bae3-5703a18b90e1",
    "relationship--e8bad1cc-0fba-51fd-abd2-cae943c239fb",
    "relationship--0adef775-32cd-577e-80e8-dfc71a48550c",
    "relationship--67b0c619-cb12-5cd2-b99e-a212eff1a8b4",
    "relationship--9389d23b-35e6-5c5e-8591-8f0f28e537d1",
    "relationship--80ebe0d5-7379-5f3a-9b65-9030d9621153",
    "relationship--7148d7f6-3588-5398-9c3c-bf294e989bb4",
  ]
  RETURN [doc]
```

You should check the IDs for each object are correct as follows;

* CAPEC-112 (`attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1`)
  * object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `exploited-using+mitre_cwe_vertex_collection/weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5+mitre_capec_vertex_collection/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1` = `relationship--08e771e1-43a8-5274-a40e-6e0c2a80a839`
* CAPEC-16 (`attack-pattern--a9dc4914-409a-4f71-80df-c5cc3923d112`)
  * object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `exploited-using+mitre_cwe_vertex_collection/weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5+mitre_capec_vertex_collection/attack-pattern--a9dc4914-409a-4f71-80df-c5cc3923d112` = `relationship--cba7ab38-92a9-5a3e-b764-6c0eee7115f4`
* CAPEC-49 (`attack-pattern--8d88a81c-bde9-4fb3-acbe-901c783d6427`)
  * object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `exploited-using+mitre_cwe_vertex_collection/weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5+mitre_capec_vertex_collection/attack-pattern--8d88a81c-bde9-4fb3-acbe-901c783d6427` = `relationship--3160ac44-e035-501c-bae3-5703a18b90e1`
* CAPEC-55 (`attack-pattern--a390cb72-b4de-4750-ae05-be556c89f4be`)
  * object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `exploited-using+mitre_cwe_vertex_collection/weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5+mitre_capec_vertex_collection/attack-pattern--a390cb72-b4de-4750-ae05-be556c89f4be` = `relationship--e8bad1cc-0fba-51fd-abd2-cae943c239fb`
* CAPEC-555 (`attack-pattern--06e8782a-87af-4863-b6b1-99e09edda3be`)
  * object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `exploited-using+mitre_cwe_vertex_collection/weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5+mitre_capec_vertex_collection/attack-pattern--06e8782a-87af-4863-b6b1-99e09edda3be` = `relationship--0adef775-32cd-577e-80e8-dfc71a48550c`
* CAPEC-561 (`attack-pattern--f2654def-b86d-4ddb-888f-de6b50a103a2`)
  * object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `exploited-using+mitre_cwe_vertex_collection/weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5+mitre_capec_vertex_collection/attack-pattern--f2654def-b86d-4ddb-888f-de6b50a103a2` = `relationship--67b0c619-cb12-5cd2-b99e-a212eff1a8b4`
* CAPEC-565 (`attack-pattern--f724f0f3-20e6-450c-be4a-f373ea08834d`)
  * object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `exploited-using+mitre_cwe_vertex_collection/weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5+mitre_capec_vertex_collection/attack-pattern--f724f0f3-20e6-450c-be4a-f373ea08834d` = `relationship--9389d23b-35e6-5c5e-8591-8f0f28e537d1`
* CAPEC-70 (`attack-pattern--8c7bab16-5ecd-4778-9b04-c185bceed170`)
  * object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `exploited-using+mitre_cwe_vertex_collection/weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5+mitre_capec_vertex_collection/attack-pattern--8c7bab16-5ecd-4778-9b04-c185bceed170` = `relationship--80ebe0d5-7379-5f3a-9b65-9030d9621153`
* CAPEC-509 (`attack-pattern--9197c7a2-6a03-40da-b2a6-df5f1d69e8fb`)
  * object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `exploited-using+mitre_cwe_vertex_collection/weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5+mitre_capec_vertex_collection/attack-pattern--9197c7a2-6a03-40da-b2a6-df5f1d69e8fb` = `relationship--7148d7f6-3588-5398-9c3c-bf294e989bb4`

### TEST 3.2 Adding a new CAPEC to a CWE

Here we update CWE-521 (`weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5`) with one new object (CAPEC-10 `attack-pattern--4a29d66d-8617-4382-b456-578ecdb1609e`)

```shell
python3 stix2arango.py \
  --file design/mvp/tests/cwe-updated.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_cwe \
  --stix2arango_note update \
  --ignore_embedded_relationships true
```

```shell
python3 arango_cti_processor.py \
  --relationship cwe-capec
```

```sql
FOR doc IN mitre_cwe_vertex_collection
  FILTER doc.id == "weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5"
  RETURN [doc]
```

Should return 2 results, the new and the old object.

```sql
FOR doc IN mitre_cwe_edge_collection
  FILTER doc._is_latest == false
  AND doc.relationship_type == "exploited-using"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5"
  RETURN [doc]
```

Should return 9 results, the old objects in 3.1.

```sql
FOR doc IN mitre_cwe_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "exploited-using"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5"
  RETURN [doc]
```

Should return 10 results, as this object now has 10 CWEs

```sql
FOR doc IN mitre_cwe_edge_collection
  FILTER doc.relationship_type == "exploited-using"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5"
  RETURN [doc]
```

Should return all 19 objects.

### TEST 4.1: Validate ATT&CK Attack Pattern -> CAPEC Attack Pattern relationship (`attack-capec`)

Delete any old data:

```shell
python3 design/mvp/test-helpers/remove-all-collections.py
```

Import required data:

```shell
python3 stix2arango.py  \
  --file backfill_data/mitre_attack_enterprise/enterprise-attack-v14_1.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_attack_enterprise \
  --stix2arango_note v14.1 \
  --ignore_embedded_relationships true
python3 stix2arango.py  \
  --file backfill_data/mitre_attack_ics/ics-attack-v14_1.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_attack_ics \
  --stix2arango_note v14.1 \
  --ignore_embedded_relationships true && \
python3 stix2arango.py  \
  --file backfill_data/mitre_attack_mobile/mobile-attack-v14_1.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_attack_mobile \
  --stix2arango_note v14.1 \
  --ignore_embedded_relationships true && \
python3 stix2arango.py  \
  --file backfill_data/mitre_capec/stix-capec-v3_9.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_capec \
  --stix2arango_note v3.9 \
  --ignore_embedded_relationships true
```

Run the script:

```shell
python3 arango_cti_processor.py \
  --relationship attack-capec
```

```sql
FOR doc IN UNION(
    (FOR d IN mitre_attack_enterprise_edge_collection RETURN d),
    (FOR d IN mitre_attack_ics_edge_collection RETURN d),
    (FOR d IN mitre_attack_mobile_edge_collection RETURN d)
)
  FILTER doc._is_latest == true
  AND doc.relationship_type == "relies-on"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 36 results (see `test-data-research.md` for how to calculate this) -- all the generated objects created by arango_cti_processor.

To check objects are created as expected, you can pick a ATT&CK object with CAPEC references and then check all the SROs for CAPECs are generated for it, as follows...

T1162: `attack-pattern--36675cd3-fe00-454c-8516-aebecacbe9d9` (Enterprise Vertex) has a link to CAPEC-564 (`attack-pattern--b63b2869-11e6-4849-8ddf-ae2557bf554b`)

```sql
FOR doc IN UNION(
    (FOR d IN mitre_attack_enterprise_edge_collection RETURN d),
    (FOR d IN mitre_attack_ics_edge_collection RETURN d),
    (FOR d IN mitre_attack_mobile_edge_collection RETURN d)
)
  FILTER doc._is_latest == true
  AND doc.relationship_type == "relies-on"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "attack-pattern--36675cd3-fe00-454c-8516-aebecacbe9d9"
  RETURN [doc]
```

Should return 1 result.

```sql
FOR doc IN UNION(
    (FOR d IN mitre_attack_enterprise_edge_collection RETURN d),
    (FOR d IN mitre_attack_ics_edge_collection RETURN d),
    (FOR d IN mitre_attack_mobile_edge_collection RETURN d)
)
  FILTER doc._is_latest == true
  AND doc.relationship_type == "relies-on"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "attack-pattern--36675cd3-fe00-454c-8516-aebecacbe9d9"
  AND doc.id == "relationship--6c3e4427-b4fc-5968-91a1-f5072299e876"
  RETURN doc
```

Check the ID is correct:

* `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `relies-on+mitre_attack_enterprise_vertex_collection/attack-pattern--36675cd3-fe00-454c-8516-aebecacbe9d9+mitre_capec_vertex_collection/attack-pattern--b63b2869-11e6-4849-8ddf-ae2557bf554b` = `relationship--6c3e4427-b4fc-5968-91a1-f5072299e876`

### TEST 5.1: Validate CVE Vulnerability -> CWE Weakness Relationship

Delete any old data:

```shell
python3 design/mvp/test-helpers/remove-all-collections.py
```

```shell
python3 stix2arango.py  \
    --file backfill_data/mitre_cwe/cwe-bundle-4_13.json \
    --database arango_cti_processor_standard_tests \
    --collection mitre_cwe \
    --stix2arango_note v4.13 \
    --ignore_embedded_relationships true && \
python3 stix2arango.py  \
  --file design/mvp/tests/cve-bundle-for-sigma-rules.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cve \
  --ignore_embedded_relationships true
```

```shell
python3 arango_cti_processor.py \
  --relationship cve-cwe
```

You will see one `ERROR - AQL exception in the query` error on this run. That's because one CVE has a duplicate CWE reference.

```sql
FOR doc IN nvd_cve_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "exploited-using"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 3 results generated by arango_cti_processor

To check objects are created as expected, you can pick a CVE object with CWE references and then check all the SROs for CWESs are generated for it, as follows...

CVE-2023-22518 (`vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6`) has two CWEs

* CWE-863 (`weakness--b6cae21a-55f9-5280-a5e9-8c367a004e63`)
* CWE-863

Note, due to errors in the NVD data, this is a duplicate. So expected only one relationship created

```sql
FOR doc IN nvd_cve_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "exploited-using"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
  RETURN [doc]
```

Should return 1 result. As CVE-2023-22518 only has one CWE; CWE-863

```sql
FOR doc IN nvd_cve_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "exploited-using"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
  AND doc.id == "relationship--d775e730-b349-5fba-8080-cd5f57f1dc3c"
  RETURN [doc]
```

Check the ID of that SRO is correct as follows;

* CWE-862: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `exploited-using+nvd_cve_vertex_collection/vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6+mitre_cwe_vertex_collection/weakness--b6cae21a-55f9-5280-a5e9-8c367a004e63` = `relationship--d775e730-b349-5fba-8080-cd5f57f1dc3c`  


### TEST 5.2: Add CWE to CVE Vulnerability

Adds CWE-787 to vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6 (now has 2 CWE refs total, used to be 1 just CWE-863)

```shell
python3 stix2arango.py  \
  --file design/mvp/tests/cve-updated-with-cwe.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cve \
  --ignore_embedded_relationships true
```

```shell
python3 arango_cti_processor.py \
  --relationship cve-cwe
```

```sql
FOR doc IN nvd_cve_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "exploited-using"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
  RETURN [doc]
```

Should return 2 results. As CVE-2023-22518 now has two CWEs; CWE-863 and CWE-787

```sql
FOR doc IN nvd_cve_edge_collection
  FILTER doc._is_latest == false
  AND doc.relationship_type == "exploited-using"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
  RETURN [doc]
```

Should return one result as old version of CVE-2023-22518 only had CWE-863

### TEST 5.3: Remove all CWEs from CVE Vulnerability

Removes all CWEs from vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6 (now has 0 CWE refs total)

```shell
python3 stix2arango.py  \
  --file design/mvp/tests/cve-updated-with-removed-cwe.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cve \
  --ignore_embedded_relationships true
```

```shell
python3 arango_cti_processor.py \
  --relationship cve-cwe
```

```sql
FOR doc IN nvd_cve_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "exploited-using"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
  RETURN [doc]
```

Should return 0 results. As CVE-2023-22518 now has no CWEs

```sql
FOR doc IN nvd_cve_edge_collection
  FILTER doc._is_latest == false
  AND doc.relationship_type == "exploited-using"
  AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.source_ref == "vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
  RETURN [doc]
```

Should return 3 results, 2 entries for the old CWEs that were latest in 5.2 and 1 entry for the old CWE that was present in 5.1.

### TEST 6.1: Validate CVE Indicator -> CPE Software Relationship

Delete any old data:

```shell
python3 design/mvp/test-helpers/remove-all-collections.py
```

Import required data:

```shell
python3 stix2arango.py  \
  --file design/mvp/tests/cve-bundle-for-sigma-rules.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cve \
  --ignore_embedded_relationships true && \
python3 stix2arango.py  \
  --file design/mvp/tests/cpe-bundle-for-cves.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cpe \
  --ignore_embedded_relationships true
```

Run the script:

```shell
python3 arango_cti_processor.py \
  --relationship cve-cpe
```

```sql
FOR doc IN nvd_cve_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "pattern-contains"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 6 objects (see test-data-research.md for info)

```sql
FOR doc IN nvd_cve_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "pattern-contains"
  AND doc.source_ref == "indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 2 results, as has 2 CPEs in Pattern

```sql
FOR doc IN nvd_cve_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "pattern-contains"
  AND doc.source_ref == "indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
  AND doc.id IN [
    "relationship--e1dc49aa-f82a-5119-9917-c4b6e4526ba8",
    "relationship--ad350647-5fd5-50ba-bc6c-6247dfbd1144"
  ]
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Same search (so should return results) used to check the IDs generated correctly;

* `cpe:2.3:a:atlassian:confluence_server:7.19.9:*:*:*:*:*:*:*`
  * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `pattern-contains+nvd_cve_vertex_collection/indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6+nvd_cpe_vertex_collection/software--50fa0834-9c63-5b0f-bf0e-dce02183253a` = `relationship--e1dc49aa-f82a-5119-9917-c4b6e4526ba8`
* `cpe:2.3:a:atlassian:confluence_server:7.19.7:*:*:*:*:*:*:*`
  * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `pattern-contains+nvd_cve_vertex_collection/indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6+nvd_cpe_vertex_collection/software--23b14f0d-c539-50bc-bdc2-38d68d849732` = `relationship--ad350647-5fd5-50ba-bc6c-6247dfbd1144`

### TEST 6.2: Add new CPE to CVE object

Adds `software:cpe='cpe:2.3:a:schollz:croc:9.6.5:*:*:*:*:*:*:*'` to `indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6`. Used to have 2 patterns, so now has 3.

```shell
python3 stix2arango.py  \
  --file design/mvp/tests/new-cpe-in-cve.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cve \
  --ignore_embedded_relationships true
```

Run the script:

```shell
python3 arango_cti_processor.py \
  --relationship cve-cpe
```

```sql
FOR doc IN nvd_cve_vertex_collection
  FILTER doc.id == "indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
  RETURN [doc]
```

Should return 2 results, the new and old version of `indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6` (CVE-2023-22518)

```sql
FOR doc IN nvd_cve_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "pattern-contains"
  AND doc.source_ref == "indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 3 results, as now has 3 CPEs in Pattern

```sql
FOR doc IN nvd_cve_edge_collection
  FILTER doc._is_latest == false
  AND doc.relationship_type == "pattern-contains"
  AND doc.source_ref == "indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 2 results, as the original indicator before update has 2 CPEs in pattern.

### TEST 6.3: Remove CPE from CVE object

Removes `software:cpe='cpe:2.3:a:schollz:croc:9.6.5:*:*:*:*:*:*:*'` (added in 6.2) from `indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6`

```shell
python3 stix2arango.py  \
  --file design/mvp/tests/removed-cpe-in-cve.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cve \
  --ignore_embedded_relationships true
```

Run the script:

```shell
python3 arango_cti_processor.py \
  --relationship cve-cpe
```

```sql
FOR doc IN nvd_cve_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "pattern-contains"
  AND doc.source_ref == "indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 2 results, as latest Indicator has 2 CPEs in Pattern

```sql
FOR doc IN nvd_cve_edge_collection
  FILTER doc._is_latest == false
  AND doc.relationship_type == "pattern-contains"
  AND doc.source_ref == "indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 5 result, the 2 old one from 5.2 and 3 old ones from this update 5.3.

### TEST 7.1: Test Sigma Rule Indicator to ATT&CK Attack Pattern relationship

Delete any old data:

```shell
python3 design/mvp/test-helpers/remove-all-collections.py
```

Import required data:

```shell
python3 stix2arango.py  \
  --file backfill_data/mitre_attack_enterprise/enterprise-attack-v14_1.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_attack_enterprise \
  --stix2arango_note v14.1 \
  --ignore_embedded_relationships true
python3 stix2arango.py  \
  --file backfill_data/mitre_attack_ics/ics-attack-v14_1.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_attack_ics \
  --stix2arango_note v14.1 \
  --ignore_embedded_relationships true && \
python3 stix2arango.py  \
  --file backfill_data/mitre_attack_mobile/mobile-attack-v14_1.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_attack_mobile \
  --stix2arango_note v14.1 \
  --ignore_embedded_relationships true && \
python3 stix2arango.py  \
  --file backfill_data/sigma_rules/sigma-rule-bundle.json \
  --database arango_cti_processor_standard_tests \
  --collection sigma_rules \
  --ignore_embedded_relationships true
```

Run the script:

```shell
python3 arango_cti_processor.py \
  --relationship sigma-attack
```

```sql
RETURN LENGTH(
  FOR doc IN sigma_rules_edge_collection
    FILTER doc._is_latest == true
    AND doc.relationship_type == "detects"
    RETURN [doc]
)
```

Expects 14437 results (see test-data-research.md for why)

```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--49150a4c-d831-51fa-9f61-aede5570a969"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

The `indicator--49150a4c-d831-51fa-9f61-aede5570a969` has two ATT&CK references, `attack.t1016` and `attack.discovery`, which should create 5 SROs...

Enterprise

* `attack.t1016` (`course-of-action--684feec3-f9ba-4049-9d8f-52d52f3e0e40`)
  * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--49150a4c-d831-51fa-9f61-aede5570a969+mitre_attack_enterprise_vertex_collection/course-of-action--684feec3-f9ba-4049-9d8f-52d52f3e0e40` = `relationship--00ce4b29-1c68-59cf-9ec4-49fe9e7eaff6`
* `attack.t1016` (`attack-pattern--707399d6-ab3e-4963-9315-d9d3818cd6a0`)
  * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--49150a4c-d831-51fa-9f61-aede5570a969+mitre_attack_enterprise_vertex_collection/attack-pattern--707399d6-ab3e-4963-9315-d9d3818cd6a0` = `relationship--3dce842a-fd66-562f-81c0-d2351f787d0a`
* `attack.discovery` (TA0007) (`x-mitre-tactic--c17c5845-175e-4421-9713-829d0573dbc9`)
  * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--49150a4c-d831-51fa-9f61-aede5570a969+mitre_attack_enterprise_vertex_collection/x-mitre-tactic--c17c5845-175e-4421-9713-829d0573dbc9` = `relationship--fecb5591-2cc4-5557-9092-06f3ae5728ea`

ICS

* `attack.t1016`: none
* `attack.discovery` (TA0102) (`x-mitre-tactic--696af733-728e-49d7-8261-75fdc590f453`)
  * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--49150a4c-d831-51fa-9f61-aede5570a969+mitre_attack_ics_vertex_collection/x-mitre-tactic--696af733-728e-49d7-8261-75fdc590f453` = `relationship--6f7e0e11-02fb-5ad0-b0fd-b04deab4c8d6`

Mobile

* `attack.t1016`: none
* `attack.discovery` (TA0032) (`x-mitre-tactic--d418cdeb-1b9f-4a6b-a15d-2f89f549f8c1`)
  * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--49150a4c-d831-51fa-9f61-aede5570a969+mitre_attack_mobile_vertex_collection/x-mitre-tactic--d418cdeb-1b9f-4a6b-a15d-2f89f549f8c1` = `relationship--f549d020-7c11-528d-ab25-1cb868fc2f6e`


```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--49150a4c-d831-51fa-9f61-aede5570a969"
  AND doc.id IN [
    "relationship--00ce4b29-1c68-59cf-9ec4-49fe9e7eaff6",
    "relationship--3dce842a-fd66-562f-81c0-d2351f787d0a",
    "relationship--fecb5591-2cc4-5557-9092-06f3ae5728ea",
    "relationship--6f7e0e11-02fb-5ad0-b0fd-b04deab4c8d6",
    "relationship--f549d020-7c11-528d-ab25-1cb868fc2f6e"
  ]
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Check passing the correct IDs still returns 5 results.

Now another test...

`indicator--f85a0947-bf4e-5e19-b67e-6652a1277f61` has a links to:

* `attack.defense_evasion`:
  * `x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a` (enterprise) 
  * `x-mitre-tactic--987cda6d-eb77-406b-bf68-bcb5f3d2e1df` (mobile)
* `attack.t1218.001`: `attack-pattern--a6937325-9321-4e2e-bb2b-3ed2d40b2a9d` (enterprise)

```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--f85a0947-bf4e-5e19-b67e-6652a1277f61"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 3 results.

Now another test...

```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--afcd1642-b090-511f-8805-78f54d9aae3a"
  RETURN [doc]
```

```json
"attack.persistence",
"attack.g0049",
"attack.t1053.005",
"attack.s0111",
"attack.t1543.003",
"attack.defense_evasion",
"attack.t1112",
"attack.command_and_control",
"attack.t1071.004",
"detection.emerging_threats"
```

Expect 16 results (note, one results in dupe IDs, but collections are different)

indicator--afcd1642-b090-511f-8805-78f54d9aae3a has links to:

* attack.persistence
  * x-mitre-tactic--5bc1d813-693e-4823-9961-abf9af4b0e92 (enterprise)
  * x-mitre-tactic--78f1d2ae-a579-44c4-8fc5-3e1775c73fac (ics)
  * x-mitre-tactic--363bbeff-bb2a-4734-ac74-d6d37202fe54 (mobile)
* attack.defense_evasion
  * x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a (enterprise)
  * x-mitre-tactic--987cda6d-eb77-406b-bf68-bcb5f3d2e1df (mobile)
* attack.command_and_control
  * x-mitre-tactic--f72804c5-f15a-449e-a5da-2eecd181f813 (enterprise)
  * x-mitre-tactic--97c8ff73-bd14-4b6c-ac32-3d91d2c41e3f (ics)
  * x-mitre-tactic--3f660805-fa2e-42e8-8851-57f9e9b653e3 (mobile)
* attack.g0049
  * intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d (enterprise)
  * intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d (ics) DUPLICATE IDs
* attack.t1053.005
  * attack-pattern--005a06c6-14bf-4118-afa0-ebcd8aebb0c9 (enterprise)
* attack.s0111
  * tool--c9703cd3-141c-43a0-a926-380082be5d04 (enterprise)
* attack.t1543.003
  * attack-pattern--2959d63f-73fd-46a1-abd2-109d7dcede32 (enterprise)
* attack.t1112
  * course-of-action--ed202147-4026-4330-b5bd-1e8dfa8cf7cc (enterprise)
  * attack-pattern--57340c81-c025-4189-8fa0-fc7ede51bae4 (enterprise)
* attack.t1071.004
  * attack-pattern--1996eef1-ced3-4d7f-bf94-33298cabbf72 (enterprise)

### TEST 7.2: Update Sigma Rule Indicator adding a new ATT&CK pattern

Adds attack.t1543.003 (1 result) to indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1. Used to have 2 attack.initial_access (1 entry in each matrix = 3), attack.t1190 (2 in enterprise) so now has 3.

```shell
python3 stix2arango.py  \
  --file design/mvp/tests/sigma-rules-with-NEW-cve.json \
  --database arango_cti_processor_standard_tests \
  --collection sigma_rules \
  --ignore_embedded_relationships true
```

Run the script:

```shell
python3 arango_cti_processor.py \
  --relationship sigma-attack
```

```sql
FOR doc IN sigma_rules_vertex_collection
  FILTER doc.id == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  RETURN [doc]
```

Should return 2 results, the new and old object.

```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == false
  AND doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 5 objects, the old versions in 7.1

```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should now return 6 results:

* attack.initial_access
  * x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca (enterprise)
  * x-mitre-tactic--69da72d2-f550-41c5-ab9e-e8255707f28a (ics)
  * x-mitre-tactic--10fa8d8d-1b04-4176-917e-738724239981 (mobile)
* attack.t1190
  * course-of-action--65da1eb6-d35d-4853-b280-98a76c0aef53 (enterprise)
  * attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c (enterprise)
* attack.t1543.003
  * attack-pattern--2959d63f-73fd-46a1-abd2-109d7dcede32 (enterprise)


```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 11 results (5 old, 6 new).

### TEST 7.3: Update Sigma Rule Indicator removing all ATT&CK pattern

Removes all attack objects from indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1

```shell
python3 stix2arango.py  \
  --file design/mvp/tests/sigma-rules-with-NO-cve.json \
  --database arango_cti_processor_standard_tests \
  --collection sigma_rules \
  --ignore_embedded_relationships true
```

Run the script:

```shell
python3 arango_cti_processor.py \
  --relationship sigma-attack
```

```sql
FOR doc IN sigma_rules_vertex_collection
  FILTER doc.id == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  RETURN [doc]
```

Should return 3 results, the new and 2 old objects.

```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 0 results, as not ATT&CK objects in newest version of Sigma rule.

```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == false
  AND doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return the 11 old objects (5 from 7.1, and 6 from 7.2).

### TEST 8.1: Test Sigma Rule Indicator to CVE Vulnerability 

Delete any old data:

```shell
python3 design/mvp/test-helpers/remove-all-collections.py
```

Import required data:

```shell
python3 stix2arango.py  \
  --file design/mvp/tests/sigma-rules-with-cves.json \
  --database arango_cti_processor_standard_tests \
  --collection sigma_rules \
  --ignore_embedded_relationships true && \
python3 stix2arango.py  \
  --file design/mvp/tests/cve-bundle-for-sigma-rules.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cve \
  --ignore_embedded_relationships true
```

Run the script:

```shell
python3 arango_cti_processor.py \
  --relationship sigma-cve
```

```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "detects"
  RETURN [doc]
```

Expecting 4 results (see test-data-research.md for info as to why).

`indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1` links to `cve.2022.26134` (`vulnerability--b4fd2041-12ff-5a64-9c00-51ba39b29fe4`) and `cve.2021.26084` (`vulnerability--ff040ea3-f2d9-5d38-80ae-065a2db41e64`)

```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should only return two results. Should not link to any indicator objects.

```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  AND doc.id IN [
    "relationship--23d454f2-0db1-571b-a85e-6b1c6d413357",
    "relationship--f5773e09-7b38-56b1-a574-01861d597f04"
  ]
  RETURN [doc]
```

Check the IDs

* `CVE-2022-26134`: `vulnerability--b4fd2041-12ff-5a64-9c00-51ba39b29fe4`
  * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1+nvd_cve_vertex_collection/vulnerability--b4fd2041-12ff-5a64-9c00-51ba39b29fe4` = `relationship--23d454f2-0db1-571b-a85e-6b1c6d413357`
* `CVE-2021-26084`: `vulnerability--ff040ea3-f2d9-5d38-80ae-065a2db41e64`
  * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1+nvd_cve_vertex_collection/vulnerability--ff040ea3-f2d9-5d38-80ae-065a2db41e64` = `relationship--f5773e09-7b38-56b1-a574-01861d597f04`

### TEST 8.2: Update Sigma Rule Indicator with another CVE Vulnerability 

```shell
python3 stix2arango.py  \
  --file design/mvp/tests/sigma-rules-with-NEW-cve.json \
  --database arango_cti_processor_standard_tests \
  --collection sigma_rules \
  --ignore_embedded_relationships true
```

Adds cve.2023.43621 to indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1. Used to have 2 CVEs in 8.1 (cve.2022.26134, cve.2021.26084) so now has 3.

Run the script:

```shell
python3 arango_cti_processor.py \
  --relationship sigma-cve
```

```sql
FOR doc IN sigma_rules_vertex_collection
  FILTER doc.id == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  RETURN [doc]
```

Should return 2 objects, the new and the old version of the indicator.

```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 3 results. 

```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == false
  AND doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 2 results (the two old objects from 8.1)

### TEST 8.3: Remove all CVEs from Sigma rule

```shell
python3 stix2arango.py  \
  --file design/mvp/tests/sigma-rules-with-NO-cve.json \
  --database arango_cti_processor_standard_tests \
  --collection sigma_rules \
  --ignore_embedded_relationships true
```

Removes all CVEs from indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1. Used to have 3 CVEs in 8.2.

Run the script:

```shell
python3 arango_cti_processor.py \
  --relationship sigma-cve
```

```sql
FOR doc IN sigma_rules_vertex_collection
  FILTER doc.id == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  RETURN [doc]
```

Should return 3 objects, the new and the 2 old versions of the indicator.

```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == true
  AND doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 0 results (as no CVEs in latest version of Sigma Rule)

```sql
FOR doc IN sigma_rules_edge_collection
  FILTER doc._is_latest == false
  AND doc.relationship_type == "detects"
  AND doc.source_ref == "indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1"
  AND doc.object_marking_refs == [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
  RETURN [doc]
```

Should return 5 results, the 3 old objects from 8.2 and 2 old objects from 8.1.

### TEST 9.1: Test CPE Groups

Delete any old data:

```shell
python3 design/mvp/test-helpers/remove-all-collections.py
```

Import required data:

```shell
python3 stix2arango.py  \
  --file design/mvp/tests/sample-cpe-bundle.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cpe \
  --ignore_embedded_relationships true
```

Run the script:

```shell
python3 arango_cti_processor.py \
  --relationship cpe-groups
```

```sql
FOR doc IN nvd_cpe_vertex_collection
    FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc._arango_cti_processor_note == "cpe-groups"
    AND doc.name LIKE "Product:%"
    AND doc.object_marking_refs == [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
    RETURN doc.name
```

Should return 202 results, as 202 unique software objects in dataset

```sql
FOR doc IN nvd_cpe_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc.type == "software"
  LET cpe_parts = SPLIT(doc.cpe, ":")
  LET product = cpe_parts[4]
  FILTER product == "chrome"
  RETURN doc.id
```

Will return 9 results for IDs of software objects where product = chrome. 

For the product grouping object for this software (chrome) the ID will be: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `chrome` = `grouping--9a385c8c-608f-5abe-8e93-9af359a02397`

```sql
FOR doc IN nvd_cpe_vertex_collection
    FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc._arango_cti_processor_note == "cpe-groups"
    AND doc.id == "grouping--9a385c8c-608f-5abe-8e93-9af359a02397"
    AND doc.object_marking_refs == [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
    RETURN [doc]
```

Should return 1 result. The object `object_refs` should have 9 `software` objects representing the 9 software versions of chrome that exist.

```sql
FOR doc IN nvd_cpe_vertex_collection
    FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc._arango_cti_processor_note == "cpe-groups"
    AND doc.name LIKE "Vendor:%"
    AND doc.object_marking_refs == [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
    RETURN doc.name
```

Should return 175 results, as 175 unique vendor names in dataset.

```sql
FOR doc IN nvd_cpe_vertex_collection
  FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc._arango_cti_processor_note == "cpe-groups"
    AND doc.name LIKE "Vendor:%"
  COLLECT name = doc.name WITH COUNT INTO count
  SORT count DESC
  RETURN {name, count}
```

Should return 175 results, each with a count of 1.

```sql
FOR doc IN nvd_cpe_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc.type == "software"
  LET cpe_parts = SPLIT(doc.cpe, ":")
  LET vendor = cpe_parts[3]
  LET product = cpe_parts[4]
  FILTER vendor == "google"
  RETURN product
```

Will return 11 results for IDs of software objects where vendor = google. There are 3 unique products (chrome_os, chrome, drive) thus expecting 3 `object_refs` to these objects.

```sql
FOR doc IN nvd_cpe_vertex_collection
    FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc._arango_cti_processor_note == "cpe-groups"
    AND doc.id == "grouping--1e39385c-96f3-5511-8601-1b58c86ceb08"
    AND doc.object_marking_refs == [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
    RETURN [doc]
```

Should return 1 grouping object.

For the grouping object the `id` should be `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `google` = `grouping--1e39385c-96f3-5511-8601-1b58c86ceb08`

The `object_refs` should be:

* `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `drive` = `c0f2c5c6-3c85-54c5-8f93-97c0d6c3b7c0`
* `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `chrome_os` = `1e840f28-abb5-510a-9150-7d98a6b48413`
* `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `chrome` = `9a385c8c-608f-5abe-8e93-9af359a02397`

### TEST 9.2: Add a new product to an existing vendor

This adds a 2 new products (softwares) for vendor = google

* `software--75a12f40-ebf2-4bfb-99e1-eb41ddbc81dc` brand new product with vendor = google
* `software--a11b7906-7775-47ea-a97d-55c3968d2c9f` a new version of vendor = google, product = chrome

```shell
python3 stix2arango.py  \
  --file design/mvp/tests/cpe-new-product.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cpe \
  --ignore_embedded_relationships true
```

```shell
python3 arango_cti_processor.py \
  --relationship cpe-groups
```

Thus expect the Vendor Grouping object to be updated with new ID, and also new product Grouping object created for the new product.

```sql
FOR doc IN nvd_cpe_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc.type == "software"
  LET cpe_parts = SPLIT(doc.cpe, ":")
  LET vendor = cpe_parts[3]
  LET product = cpe_parts[4]
  FILTER vendor == "google"
  RETURN [doc]
```

Will return 13 results (2 new objects, from 11 in test 9.1)

```sql
FOR doc IN nvd_cpe_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc.type == "software"
    AND doc.id IN [
      "software--75a12f40-ebf2-4bfb-99e1-eb41ddbc81dc",
      "software--a11b7906-7775-47ea-a97d-55c3968d2c9f"
    ]
  RETURN [doc]
```

Here are the two new objects.

```sql
FOR doc IN nvd_cpe_vertex_collection
  FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc._arango_cti_processor_note == "cpe-groups"
    AND doc.type == "grouping"
    AND doc.name == "Product: new"
    RETURN [doc]
```

Lets start by looking at the brand new product (`new`). This search should return one result for the grouping object that should have been created for it.

We expect it to have the ID: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `new` = `grouping--5a242cbb-1bf3-596e-abc9-18747e6c5261`

```sql
FOR doc IN nvd_cpe_vertex_collection
    FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc.type == "grouping"
    AND doc._arango_cti_processor_note == "cpe-groups"
    AND doc.id == "grouping--1e39385c-96f3-5511-8601-1b58c86ceb08"
    AND doc.object_marking_refs == [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
    RETURN [doc]
```
This search returns the Google product grouping (`grouping--1e39385c-96f3-5511-8601-1b58c86ceb08`).

This should return 2 objects (the old Google grouping object, and the new one, with the new grouping object for product `new` added to `object_refs`)

```sql
FOR doc IN nvd_cpe_vertex_collection
    FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc._is_latest == true
    AND doc.type == "grouping"
    AND doc._arango_cti_processor_note == "cpe-groups"
    AND doc.id == "grouping--1e39385c-96f3-5511-8601-1b58c86ceb08"
    AND doc.object_marking_refs == [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
    RETURN [doc]
```

Same search, but this time only showing latest version which should have 4 object_refs including `grouping--5a242cbb-1bf3-596e-abc9-18747e6c5261` for product `new` added in update.

```sql
FOR doc IN nvd_cpe_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc.type == "software"
  LET cpe_parts = SPLIT(doc.cpe, ":")
  LET product = cpe_parts[4]
  FILTER product == "chrome"
  RETURN doc.id
```

Will now return 10 results (9 previously) for IDs of software objects where product = chrome.

```sql
FOR doc IN nvd_cpe_vertex_collection
    FILTER doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc._arango_cti_processor_note == "cpe-groups"
    AND doc.id == "grouping--9a385c8c-608f-5abe-8e93-9af359a02397"
    AND doc.object_marking_refs == [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
    RETURN [doc]
```

This should return 2 objects (the old Chrome grouping object, and the new one, with the new software added to `object_refs`.

```sql
FOR doc IN nvd_cpe_vertex_collection
    FILTER doc._is_latest == true
    AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc._arango_cti_processor_note == "cpe-groups"
    AND doc.id == "grouping--9a385c8c-608f-5abe-8e93-9af359a02397"
    AND doc.object_marking_refs == [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
    RETURN [doc]
```

Check the `object_refs` now have 10 entries (was 9 for 9.1) the new Chrome version object has ID `software--a11b7906-7775-47ea-a97d-55c3968d2c9f`.


### Volume tests

Whilst the previous tests cover the logic of the script, it's also important we test it at scale (ultimately how it will be used in real life).

To do this, install [stix2arango](https://github.com/muchdogesec/stix2arango/) separately and run the following to import all data;

```shell
python3 utilities/arango_cti_processor/insert_archive_attack_enterprise.py \
  --database arango_cti_processor_volume_tests \
  --ignore_embedded_relationships false && \
python3 utilities/arango_cti_processor/insert_archive_attack_ics.py \
  --database arango_cti_processor_volume_tests \
  --ignore_embedded_relationships false && \
python3 utilities/arango_cti_processor/insert_archive_attack_mobile.py
  --database arango_cti_processor_volume_tests \
  --ignore_embedded_relationships false && \
python3 utilities/arango_cti_processor/insert_archive_capec.py \
  --database arango_cti_processor_volume_tests \
  --ignore_embedded_relationships false && \
python3 utilities/arango_cti_processor/insert_archive_cwe.py \
  --database arango_cti_processor_volume_tests \
  --ignore_embedded_relationships false && \
python3 utilities/arango_cti_processor/insert_archive_disarm.py \
  --database arango_cti_processor_volume_tests \
  --ignore_embedded_relationships false && \
python3 utilities/arango_cti_processor/insert_archive_locations.py \
  --database arango_cti_processor_volume_tests \
  --ignore_embedded_relationships false && \
python3 utilities/arango_cti_processor/insert_archive_sigma_rules.py \
  --database arango_cti_processor_volume_tests \
  --ignore_embedded_relationships false && \
python3 utilities/arango_cti_processor/insert_archive_yara_rules.py \
  --database arango_cti_processor_volume_tests \
  --ignore_embedded_relationships false && \
python3 utilities/arango_cti_processor/insert_archive_cve.py \
  --database arango_cti_processor_volume_tests \
  --ignore_embedded_relationships false && \
python3 utilities/arango_cti_processor/insert_archive_cpe.py \
  --database arango_cti_processor_volume_tests \
  --ignore_embedded_relationships true
```
