# Tests

To run all tests described here;

```shell
python3 tests/test_00_run_all_tests.py
```

We run this over `pytest` because some test here are no longer relevant.

## TEST 1.0 Validate CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

```shell
python3 -m unittest tests/test_01_00_capec_to_attack.py
```

## TEST 1.0.5: Perform update to change CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

This time we don't import any new data, but run the arango_cti_processor command again

This should generate 0 new objects, because the output should be identical to first run, and thus no new versions should be created.

```shell
python3 -m unittest tests/test_01_01_capec_to_attack.py
```

## TEST 1.1: Perform update to change CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

Note, test 1.0 must have been run for this test to work.

Here we provide an update to 2 objects in the CAPEC update bundle, 

* 1 is brand new CAPEC with 1 att&ck reference `attack-pattern--39b37ebd-276c-48e7-b152-d94a29599f4b` (CAPEC-999) to T1650
* 1 is an update to an existing CAPEC object (T1650 1 new att&ck reference is added) (2 previously existed T1040 and T1111) `attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a` (CAPEC-158) so now 3 attack objects.

Expected is that the new object is identified by the script and relationships generated.

For the updated objects, expected is that old SROs created by arango_cti_processor are marked as `_is_latest==false` (2 total) and 3 new objects (1 new, 2 existing recreated)

```shell
python3 -m unittest tests/test_01_1_capec_to_attack.py
```

## TEST 1.2: Perform ANOTHER update to change CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

Note, test 1.1 must have been run for this test to work.

Here we provide an update `attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a` for a second time, where 1 new att&ck reference is added (3 previously existed T1040, T1650, T1111, so 4 now with addition of T1574.010)

```shell
python3 -m unittest tests/test_01_2_capec_to_attack.py
```

## TEST 1.3 Perform ANOTHER update to change CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

Note, test 1.2 must have been run for this test to work.

This time we remove 2 of the ATT&CK references inside the CAPEC object (`attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a`), with 2 remaining T1040 and T1111 (total 4 ATT&CK links). T1650 and T1574.010 are removed (total 2 ATT&CK links). This is now the same as the original stix-capec-v3.9.json object

```shell
python3 -m unittest tests/test_01_3_capec_to_attack.py
```

## TEST 1.4 Perform ANOTHER update to change CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

Note, test 1.3 must have been run for this test to work.

This time we are adding ATT&CK references back to `attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a`. 

The doc now contains the same references as test 1.3 (4 in total): T1040, T1650, T1111, T1574.010

```shell
python3 -m unittest tests/test_01_4_capec_to_attack.py
```

## TEST 1.5 Perform ANOTHER update to change CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

Note, test 1.4 must have been run for this test to work.

This time we remove all of the ATT&CK references inside the CAPEC object (`attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a`).

```shell
python3 -m unittest tests/test_01_5_capec_to_attack.py
```

Should return 0 result, as no ATT&CK references exist in this CAPEC object now.

---

## TEST 2.0: Validate CAPEC Attack Pattern -> CWE Weakness relationship (`capec-cwe`)

```shell
python3 -m unittest tests/test_02_0_capec_to_cwe.py
```

## TEST 2.1: Add new CWE Weakness to CAPEC (`capec-cwe`)

Test 2.0 should be run beforehand.

In this file I update CAPEC-112 (`attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1`) with one new CWE; CWE-1004. It now has 4 CWE references.

```shell
python3 -m unittest tests/test_02_1_capec_to_cwe.py
```

---

## TEST 3.0: Validate CWE Weakness -> CAPEC Attack Pattern relationship (`cwe-capec`)

```shell
python3 -m unittest tests/test_03_0_cwe_to_capec.py
```

## TEST 3.1 Adding a new CAPEC to a CWE

Test 3.0 should be run beforehand.

Here we update CWE-521 (`weakness--de02e88c-42c5-5ddf-b5d1-1c8aeac79926`) with one new object (CAPEC-10 `attack-pattern--4a29d66d-8617-4382-b456-578ecdb1609e`)

```shell
python3 -m unittest tests/test_03_1_cwe_to_capec.py
```

---

## TEST 4.0: [ARCHIVED] Validate ATT&CK Attack Pattern -> CAPEC Attack Pattern relationship (`attack-capec`)

```shell
python3 -m unittest tests/test_04_0_attack_to_capec.py
```

Archived -- ATT&CK objects no longer contain references to CAPEC. Tests updated to reflect this.

---

## TEST 9.0: Test modified time min cli arg

The CLI `modified_min` argument is 2022-01-01 so the expectation is that only one SRO is created by arango_cti_processor (1 time is older than this (`2015-01-01T00:00:00.000Z`), one time is younger than this (`2024-01-01T00:00:00.000Z`))

```shell
python3 -m unittest tests/test_09_0_modified_min.py
```

## TEST 9.1: Test created time min cli arg

The CLI `created_min` argument is 2020-01-01 so the expectation is that only one SRO is created by arango_cti_processor (1 time is older than this (`2000-01-01T00:00:00.000Z`), one time is younger than this (`2022-01-01T00:00:00.000Z`))

```shell
python3 -m unittest tests/test_09_1_created_min.py
```

---

## TEST 10.0: Test IGNORE_EMBEDDED_RELATIONSHIPS = false

Uses single cwe -> capec relationships

This generates 2 SROs between CWE -> CAPEC

```shell
python3 -m unittest tests/test_10_0_ignore_embedded_relationships_f.py
```

## TEST 10.1: Test update to objects where IGNORE_EMBEDDED_RELATIONSHIPS = false

This time adds a new capec. now 3 sros create by ACTIP so 9 embedded SROs to exist.

```shell
python3 -m unittest tests/test_10_1_ignore_embedded_relationships_f.py
```

## TEST 10.2: Test removed objects where IGNORE_EMBEDDED_RELATIONSHIPS = false

Removes the added capec in 10.1, so now 2 capecs (and 6 embedded refs)

```shell
python3 -m unittest tests/test_10_2_ignore_embedded_relationships_f.py
```

---

## TEST 11.0: Test IGNORE_EMBEDDED_RELATIONSHIPS = true

```shell
python3 -m unittest tests/test_11_0_ignore_embedded_relationships_t.py
```