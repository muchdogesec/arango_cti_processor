# Tests

## TEST 1.0 Validate CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

```shell
python3 tests/delete_all_databases.py
```

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 utilities/arango_cti_processor/insert_archive_attack_enterprise.py \
  --database arango_cti_processor_standard_tests \
  --versions 14_1 && \
python3 utilities/arango_cti_processor/insert_archive_attack_ics.py \
  --database arango_cti_processor_standard_tests \
  --versions 14_1 && \
python3 utilities/arango_cti_processor/insert_archive_attack_mobile.py \
  --database arango_cti_processor_standard_tests \
  --versions 14_1 && \
python3 utilities/arango_cti_processor/insert_archive_capec.py \
  --database arango_cti_processor_standard_tests \
  --versions 3_9
```

Run the test script;

```shell
python3 -m unittest tests/test_1_0_capec_to_attack.py
```

## TEST 1.0.5: Perform update to change CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

This time we don't import any new data, but run the arango_cti_processor command again

This should generate 0 new objects, because the output should be identical to first run, and thus no new versions should be created.

Run the test script for 1.0 (results should still be the same, as nothing should have changed);

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
  --stix2arango_note v3.10
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
  --stix2arango_note v3.11
```

Run the test script;

```shell
python3 -m unittest tests/test_1_2_capec_to_attack.py
```

## TEST 1.3 Perform ANOTHER update to change CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

Note, test 1.2 must have been run for this test to work.

This time we remove 2 of the ATT&CK references inside the CAPEC object (`attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a`), with 2 remaining T1040 and T1111 (total 4 ATT&CK links). T1650 and T1574.010 are removed (total 2 ATT&CK links). This is now the same as the original stix-capec-v3.9.json object

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 stix2arango.py \
  --file tests/files/arango_cti_processor/arango-cti-capec-attack-update-3.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_capec \
  --stix2arango_note v3.12
```

Run the test script;

```shell
python3 -m unittest tests/test_1_3_capec_to_attack.py
```

## TEST 1.4 Perform ANOTHER update to change CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

Note, test 1.3 must have been run for this test to work.

This time we are adding ATT&CK references back to `attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a`. 

The doc now contains the same references as test 1.3 (4 in total): T1040, T1650, T1111, T1574.010

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 stix2arango.py \
  --file tests/files/arango_cti_processor/arango-cti-capec-attack-update-4.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_capec \
  --stix2arango_note v3.13
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
  --stix2arango_note v3.14
```

Run the test script;

```shell
python3 -m unittest tests/test_1_5_capec_to_attack.py
```

Should return 0 result, as no ATT&CK references exist in this CAPEC object now.

---

## TEST 2.0: Validate CAPEC Attack Pattern -> CWE Weakness relationship (`capec-cwe`)

```shell
python3 tests/delete_all_databases.py
```

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 utilities/arango_cti_processor/insert_archive_capec.py \
  --database arango_cti_processor_standard_tests \
  --versions 3_9 && \
python3 utilities/arango_cti_processor/insert_archive_cwe.py \
  --database arango_cti_processor_standard_tests \
  --versions 4_13
```

Run the test script;

```shell
python3 -m unittest tests/test_2_0_capec_to_cwe.py
```

## TEST 2.1: Add new CWE Weakness to CAPEC (`capec-cwe`)

Test 2.0 should be run beforehand.

In this file I update CAPEC-112 (`attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1`) with one new CWE; CWE-1004. It now has 4 CWE references.

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 stix2arango.py \
  --file tests/files/arango_cti_processor/arango-cti-capec-cwe-update-1.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_capec \
  --stix2arango_note v3.10
```

Run the test script;

```shell
python3 -m unittest tests/test_2_1_capec_to_cwe.py
```

---

## TEST 3.0: Validate CWE Weakness -> CAPEC Attack Pattern relationship (`cwe-capec`)

```shell
python3 tests/delete_all_databases.py
```

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 utilities/arango_cti_processor/insert_archive_capec.py \
  --database arango_cti_processor_standard_tests \
  --versions 3_9 && \
python3 utilities/arango_cti_processor/insert_archive_cwe.py \
  --database arango_cti_processor_standard_tests \
  --versions 4_13
```

Run the test script;

```shell
python3 -m unittest tests/test_3_0_cwe_to_capec.py
```

## TEST 3.1 Adding a new CAPEC to a CWE

Test 3.0 should be run beforehand.

Here we update CWE-521 (`weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5`) with one new object (CAPEC-10 `attack-pattern--4a29d66d-8617-4382-b456-578ecdb1609e`)

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 stix2arango.py \
  --file tests/files/arango_cti_processor/arango-cti-cwe-capec-update-1.json \
  --database arango_cti_processor_standard_tests \
  --collection mitre_capec \
  --stix2arango_note v4.14
```

Run the test script;

```shell
python3 -m unittest tests/test_3_1_capec_to_cwe.py
```

---

## TEST 4.0: Validate ATT&CK Attack Pattern -> CAPEC Attack Pattern relationship (`attack-capec`)

```shell
python3 tests/delete_all_databases.py
```

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 utilities/arango_cti_processor/insert_archive_attack_enterprise.py \
  --database arango_cti_processor_standard_tests \
  --versions 14_1 && \
python3 utilities/arango_cti_processor/insert_archive_attack_ics.py \
  --database arango_cti_processor_standard_tests \
  --versions 14_1 && \
python3 utilities/arango_cti_processor/insert_archive_attack_mobile.py \
  --database arango_cti_processor_standard_tests \
  --versions 14_1 && \
python3 utilities/arango_cti_processor/insert_archive_capec.py \
  --database arango_cti_processor_standard_tests \
  --versions 3_9
```

Run the test script;

```shell
python3 -m unittest tests/test_4_0_attack_to_capec.py
```

---

## TEST 5.0: Validate CVE Vulnerability -> CWE Weakness Relationship (`cve-cwe`)

```shell
python3 tests/delete_all_databases.py
```

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):


```shell
python3 utilities/arango_cti_processor/insert_archive_cwe.py \
  --database arango_cti_processor_standard_tests \
  --versions 4_13
```

```shell
python3 stix2arango.py  \
  --file tests/files/arango_cti_processor/condensed_cve_bundle.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cve
```

Run the test script;

```shell
python3 -m unittest tests/test_5_0_cve_to_cwe.py
```

You will see one `ERROR - AQL exception in the query` error on this run. That's because one CVE has a duplicate CWE reference. This is normal in real-world data.

## TEST 5.1: Add CWE to CVE Vulnerability

Need to run test 5.0 beforehand

Adds CWE-787 to vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6 (now has 2 CWE refs total, used to be 1 just CWE-863)

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 stix2arango.py  \
  --file tests/files/arango_cti_processor/condensed_cve_bundle-updated-1.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cve
```

Run the test script;

```shell
python3 -m unittest tests/test_5_1_cve_to_cwe.py
```

## TEST 5.2: Remove all CWEs from CVE Vulnerability

Need to run test 5.1 beforehand

Removes all CWEs from vulnerability--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6 (now has 0 CWE refs total)

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 stix2arango.py  \
  --file tests/files/arango_cti_processor/condensed_cve_bundle-updated-2.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cve \
  --ignore_embedded_relationships true
```

Run the test script;

```shell
python3 -m unittest tests/test_5_2_cve_to_cwe.py
```

---

## TEST 6.0: Validate CVE Indicator -> CPE Software Relationship (`cve-cpe`)

```shell
python3 tests/delete_all_databases.py
```

condensed_cve_bundle.json has 6 cpes

Import required data using a separate install of [stix2arango](https://github.com/muchdogesec/stix2arango/):

```shell
python3 stix2arango.py  \
  --file tests/files/arango_cti_processor/condensed_cve_bundle.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cve \
  --ignore_embedded_relationships true && \
python3 stix2arango.py  \
  --file tests/files/arango_cti_processor/condensed_cpe_bundle.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cpe \
  --ignore_embedded_relationships true
```

Run the test script;

```shell
python3 -m unittest tests/test_6_0_cve_to_cpe.py
```

## TEST 6.1: Add new CPE to CVE object

Need to run test 6.0 beforehand

Adds `software:cpe='cpe:2.3:a:schollz:croc:9.6.5:*:*:*:*:*:*:*'` to `indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6`. Used to have 2 patterns, so now has 3.

```shell
python3 stix2arango.py  \
  --file tests/files/arango_cti_processor/condensed_cpe_bundle-update-1.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cve \
  --ignore_embedded_relationships true
```

Run the test script;

```shell
python3 -m unittest tests/test_6_1_cve_to_cpe.py
```

## TEST 6.2: Remove CPE from CVE object

Need to run test 6.1 beforehand

Removes `software:cpe='cpe:2.3:a:schollz:croc:9.6.5:*:*:*:*:*:*:*'` (added in 6.2) from `indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6`

```shell
python3 stix2arango.py  \
  --file tests/files/arango_cti_processor/condensed_cpe_bundle-update-2.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cve \
  --ignore_embedded_relationships true
```

Run the test script;

```shell
python3 -m unittest tests/test_6_2_cve_to_cpe.py
```

---

## TEST 7.0: Test Sigma Rule Indicator to ATT&CK Attack Pattern relationship (`sigma-attack`)

```shell
python3 tests/delete_all_databases.py
```

Import required data:

```shell
python3 utilities/arango_cti_processor/insert_archive_attack_enterprise.py \
  --database arango_cti_processor_standard_tests \
  --versions 14_1 && \
python3 utilities/arango_cti_processor/insert_archive_attack_ics.py \
  --database arango_cti_processor_standard_tests \
  --versions 14_1 && \
python3 utilities/arango_cti_processor/insert_archive_attack_mobile.py \
  --database arango_cti_processor_standard_tests \
  --versions 14_1 && \
python3 utilities/arango_cti_processor/insert_archive_sigma_rules.py \
  --database arango_cti_processor_volume_tests \
  --versions 2024-05-13
```

Run the test script;

```shell
python3 -m unittest tests/test_7_0_sigma_to_attack.py
```

## TEST 7.1: Update Sigma Rule Indicator adding a new ATT&CK pattern

Adds attack.t1543.003 (1 result) to indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1. Used to have 2 attack.initial_access (1 entry in each matrix = 3), attack.t1190 (2 in enterprise) so now has 3 generation 6 sros total

```shell
python3 stix2arango.py  \
  --file tests/files/arango_cti_processor/sigma-rules-with-NEW-cve.json \
  --database arango_cti_processor_standard_tests \
  --collection sigmahq_rules
```

Run the test:

```shell
python3 -m unittest tests/test_7_1_sigma_to_attack.py
```

## TEST 7.2: Update Sigma Rule Indicator removing all ATT&CK pattern

Removes all attack objects from indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1

```shell
python3 stix2arango.py  \
  --file tests/files/arango_cti_processor/sigma-rules-with-NO-cve.json \
  --database arango_cti_processor_standard_tests \
  --collection sigmahq_rules
```

Run the test:

```shell
python3 -m unittest tests/test_7_2_sigma_to_attack.py
```

---

## TEST 8.0: Test Sigma Rule Indicator to CVE Vulnerability 

```shell
python3 tests/delete_all_databases.py
```

Import required data:

```shell
python3 stix2arango.py  \
  --file tests/files/arango_cti_processor/sigma-rules-with-cves.json \
  --database arango_cti_processor_standard_tests \
  --collection sigmahq_rules && \
python3 stix2arango.py  \
  --file tests/files/arango_cti_processor/condensed_cve_bundle.json \
  --database arango_cti_processor_standard_tests \
  --collection nvd_cve
```

Run the test:

```shell
python3 -m unittest tests/test_8_0_sigma_to_cve.py
```

## TEST 8.1: Update Sigma Rule Indicator with another CVE Vulnerability 

Import required data:

```shell
python3 stix2arango.py  \
  --file tests/files/arango_cti_processor/sigma-rules-with-NEW-cve.json \
  --database arango_cti_processor_standard_tests \
  --collection sigmahq_rules
```

Adds cve.2023.43621 to indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1. Used to have 2 CVEs in 8.1 (cve.2022.26134, cve.2021.26084) so now has 3.

Run the test:

```shell
python3 -m unittest tests/test_8_1_sigma_to_cve.py
```

## TEST 8.2: Remove all CVEs from Sigma rule

Import required data:

```shell
python3 stix2arango.py  \
  --file tests/files/arango_cti_processor/sigma-rules-with-NO-cve.json \
  --database arango_cti_processor_standard_tests \
  --collection sigmahq_rules
```

Removes all CVEs from indicator--74904ec1-cff3-5737-a1d4-408c789dc8b1. Used to have 3 CVEs in 8.2, 2 in 8.1, now 0 in 8.3.

```shell
python3 -m unittest tests/test_8_2_sigma_to_cve.py
```