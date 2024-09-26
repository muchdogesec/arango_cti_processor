


## 5. Sigma Rule Indicator -> ATT&CK Technique/Tactic/Malware/Group

Import the required data...

```shell
python3 stix2arango.py	\
	--file backfill_data/sigma_rules/sigma-rule-bundle.json \
	--database cti \
	--collection sigma_rules \
	--ignore_embedded_relationships true
```

```sql
LET total_count = (
    FOR doc IN sigma_rules_vertex_collection
        FILTER HAS(doc, "external_references") AND IS_ARRAY(doc.external_references)
        FOR ref IN doc.external_references
            FILTER ref.source_name == "mitre-attack"
            COLLECT WITH COUNT INTO count
            RETURN count
)

LET detailed_counts = (
    FOR doc IN sigma_rules_vertex_collection
        FILTER HAS(doc, "external_references") AND IS_ARRAY(doc.external_references)
        FOR ref IN doc.external_references
            FILTER ref.source_name == "mitre-attack"
            COLLECT ext_id = ref.external_id WITH COUNT INTO count
            SORT count DESC
            RETURN { external_id: ext_id, count: count }
)

RETURN APPEND(detailed_counts, [{ external_id: "Total", count: SUM(total_count) }])
```

Returns a list of all ATT&CK labels that exist. The sum of the count field should be 7685 (labels in total). Should return 418 unique IDs.

```sql
RETURN (
    FOR doc IN sigma_rules_vertex_collection
        FILTER HAS(doc, "external_references") AND IS_ARRAY(doc.external_references)
        FOR ref IN doc.external_references
            FILTER ref.source_name == "mitre-attack"
            COLLECT ext_id = ref.external_id
            RETURN ext_id
)
```

Same as first search returns the list ready for the next search;


```sql
LET attack_ids = ["G0010","G0020","G0022","G0032","G0044","G0046","G0047","G0049","G0060","G0069","G0080","G0091","G0093","G0125","S0002","S0005","S0029","S0039","S0040","S0075","S0106","S0108","S0111","S0139","S0154","S0190","S0195","S0246","S0349","S0363","S0402","S0404","S0482","S0508","S0575","S0592","T1001.003","T1003","T1003.001","T1003.002","T1003.003","T1003.004","T1003.005","T1003.006","T1005","T1007","T1008","T1010","T1012","T1014","T1016","T1018","T1020","T1021","T1021.001","T1021.002","T1021.003","T1021.004","T1021.005","T1021.006","T1021.007","T1027","T1027.001","T1027.002","T1027.003","T1027.004","T1027.005","T1027.009","T1027.010","T1030","T1033","T1036","T1036.002","T1036.003","T1036.004","T1036.005","T1036.006","T1036.007","T1037.001","T1037.005","T1039","T1040","T1041","T1046","T1047","T1048","T1048.001","T1048.003","T1049","T1053","T1053.002","T1053.003","T1053.005","T1055","T1055.001","T1055.003","T1055.009","T1055.012","T1056","T1056.001","T1056.002","T1057","T1059","T1059.001","T1059.002","T1059.003","T1059.004","T1059.005","T1059.006","T1059.007","T1059.009","T1068","T1069","T1069.001","T1069.002","T1069.003","T1070","T1070.001","T1070.002","T1070.003","T1070.004","T1070.005","T1070.006","T1070.008","T1071","T1071.001","T1071.004","T1072","T1074","T1074.001","T1078","T1078.001","T1078.002","T1078.003","T1078.004","T1082","T1083","T1087","T1087.001","T1087.002","T1087.004","T1090","T1090.001","T1090.002","T1090.003","T1091","T1095","T1098","T1098.001","T1098.003","T1102","T1102.001","T1102.002","T1102.003","T1104","T1105","T1106","T1110","T1110.001","T1110.002","T1112","T1113","T1114","T1114.001","T1115","T1119","T1120","T1123","T1124","T1125","T1127","T1127.001","T1132.001","T1133","T1134","T1134.001","T1134.002","T1134.003","T1134.004","T1134.005","T1135","T1136","T1136.001","T1136.002","T1136.003","T1137","T1137.002","T1137.003","T1137.006","T1140","T1176","T1185","T1187","T1189","T1190","T1195","T1195.001","T1197","T1199","T1200","T1201","T1202","T1203","T1204","T1204.001","T1204.002","T1207","T1210","T1211","T1212","T1213","T1213.003","T1216","T1216.001","T1217","T1218","T1218.001","T1218.002","T1218.003","T1218.005","T1218.007","T1218.008","T1218.009","T1218.010","T1218.011","T1218.013","T1219","T1220","T1221","T1222","T1222.001","T1222.002","T1482","T1484","T1484.001","T1485","T1486","T1489","T1490","T1491.001","T1495","T1496","T1497.001","T1498","T1499.004","T1505","T1505.002","T1505.003","T1505.004","T1505.005","T1518","T1518.001","T1525","T1526","T1528","T1529","T1531","T1537","T1539","T1542.001","T1542.003","T1543","T1543.001","T1543.002","T1543.003","T1543.004","T1546","T1546.001","T1546.002","T1546.003","T1546.004","T1546.007","T1546.008","T1546.009","T1546.010","T1546.011","T1546.012","T1546.013","T1546.014","T1546.015","T1547","T1547.001","T1547.002","T1547.003","T1547.004","T1547.005","T1547.006","T1547.008","T1547.009","T1547.010","T1547.014","T1547.015","T1548","T1548.001","T1548.002","T1548.003","T1550","T1550.001","T1550.002","T1550.003","T1552","T1552.001","T1552.002","T1552.003","T1552.004","T1552.006","T1552.007","T1553","T1553.001","T1553.002","T1553.003","T1553.004","T1553.005","T1554","T1555","T1555.001","T1555.003","T1555.004","T1555.005","T1556","T1556.002","T1556.006","T1557","T1557.001","T1558","T1558.003","T1559.001","T1559.002","T1560","T1560.001","T1561.001","T1561.002","T1562","T1562.001","T1562.002","T1562.003","T1562.004","T1562.006","T1562.007","T1562.010","T1563.002","T1564","T1564.001","T1564.002","T1564.003","T1564.004","T1564.006","T1565","T1565.001","T1565.002","T1566","T1566.001","T1566.002","T1567","T1567.001","T1567.002","T1568","T1568.002","T1569","T1569.001","T1569.002","T1570","T1571","T1572","T1573","T1574","T1574.001","T1574.002","T1574.005","T1574.006","T1574.007","T1574.008","T1574.011","T1574.012","T1578","T1578.003","T1580","T1584","T1586","T1586.003","T1587","T1587.001","T1588","T1588.002","T1589","T1590","T1590.001","T1590.002","T1591.004","T1592.004","T1593.003","T1595","T1595.002","T1599.001","T1606","T1608","T1609","T1611","T1614.001","T1615","T1620","T1621","T1622","T1649"]

LET lowercased_attack_ids = (
    FOR id IN attack_ids
        RETURN LOWER(id)
)

LET enterprise_results = (
    FOR doc IN mitre_attack_enterprise_vertex_collection
        FILTER doc._stix2arango_note != "automatically imported on collection creation"
        AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
        AND doc._is_latest == true
        AND IS_ARRAY(doc.external_references)
        FOR ext_ref IN doc.external_references
            FILTER LOWER(ext_ref.external_id) IN lowercased_attack_ids
            RETURN { external_id: ext_ref.external_id, doc: doc }
)

LET ics_results = (
    FOR doc IN mitre_attack_ics_vertex_collection
        FILTER doc._stix2arango_note != "automatically imported on collection creation"
        AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
        AND doc._is_latest == true
        AND IS_ARRAY(doc.external_references)
        FOR ext_ref IN doc.external_references
            FILTER LOWER(ext_ref.external_id) IN lowercased_attack_ids
            RETURN { external_id: ext_ref.external_id, doc: doc }
)

LET mobile_results = (
    FOR doc IN mitre_attack_mobile_vertex_collection
        FILTER doc._stix2arango_note != "automatically imported on collection creation"
        AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
        AND doc._is_latest == true
        AND IS_ARRAY(doc.external_references)
        FOR ext_ref IN doc.external_references
            FILTER LOWER(ext_ref.external_id) IN lowercased_attack_ids
            RETURN { external_id: ext_ref.external_id, doc: doc }
)

LET all_results = UNION(enterprise_results, ics_results, mobile_results)

FOR result IN all_results
    COLLECT id = result.external_id WITH COUNT INTO count
    SORT count
    RETURN { external_id: id, count }
```

Should return 404 results (number of items in list) and count of how many ATT&CK tactic objects have this id (sum is 503 in total). Multiplying number of labels by count gives: 5070.

```sql
LET tactic_names = [
    "Collection",
    "Command and Control",
    "Credential Access",
    "Defense Evasion",
    "Discovery",
    "Execution",
    "Exfiltration",
    "Impact",
    "Initial Access",
    "Lateral Movement",
    "Persistence",
    "Privilege Escalation",
    "Reconnaissance",
    "Resource Development"
]

LET enterprise_results = (
    FOR doc IN mitre_attack_enterprise_vertex_collection
        FILTER doc.type == "x-mitre-tactic"
        AND doc._is_latest == true
        AND doc.name IN tactic_names
        RETURN doc.name
)

LET ics_results = (
    FOR doc IN mitre_attack_ics_vertex_collection
        FILTER doc.type == "x-mitre-tactic"
        AND doc._is_latest == true
        AND doc.name IN tactic_names
        RETURN doc.name
)

LET mobile_results = (
    FOR doc IN mitre_attack_mobile_vertex_collection
        FILTER doc.type == "x-mitre-tactic"
        AND doc._is_latest == true
        AND doc.name IN tactic_names
        RETURN doc.name
)

LET all_results = UNION(enterprise_results, ics_results, mobile_results)

FOR name IN all_results
    COLLECT nameCount = name WITH COUNT INTO count
    RETURN { name: nameCount, count }
```

Should return 14 results (number of items in list) and count of how many ATT&CK tactic objects have this name (sum is 35 in total). Multiplying number of labels by count gives: 10476

5070 + 10476

15546 SRO results expected on first run to be generated by arango_cti_processor

#### A quick note on dupe IDs

Sometimes an ATT&CK ID persists between ATT&CK matrices. You can see these using this search;

```sql
LET enterpriseDocs = (
  FOR doc IN mitre_attack_enterprise_vertex_collection
    RETURN {id: doc._key, collection: 'mitre_attack_enterprise_vertex_collection'}
)
LET icsDocs = (
  FOR doc IN mitre_attack_ics_vertex_collection
    RETURN {id: doc._key, collection: 'mitre_attack_ics_vertex_collection'}
)
LET mobileDocs = (
  FOR doc IN mitre_attack_mobile_vertex_collection
    RETURN {id: doc._key, collection: 'mitre_attack_mobile_vertex_collection'}
)
LET combinedDocs = UNION(enterpriseDocs, icsDocs, mobileDocs)
LET aggregatedDocs = (
  FOR doc IN combinedDocs
    COLLECT id = doc.id WITH COUNT INTO counter
    FILTER counter > 1
    LET collections = (
      FOR d IN combinedDocs
        FILTER d.id == id
        RETURN d.collection
    )
    RETURN { id: id, collections: collections }
)

RETURN aggregatedDocs
```

Take one example result for a ATT&CK tag `attack.g0049`, which has objects;

* intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d (enterprise)
* intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d (ics)``

```json
    {
      "id": "intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d",
      "collections": [
        "mitre_attack_enterprise_vertex_collection",
        "mitre_attack_ics_vertex_collection"
      ]
    }
```

This should not cause a problem in the script because the two SROs being created point to different objects

e.g. indicator--afcd1642-b090-511f-8805-78f54d9aae3a has attack.g0049

So would create two SROs 

1. indicator--afcd1642-b090-511f-8805-78f54d9aae3a -> intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d
2. indicator--afcd1642-b090-511f-8805-78f54d9aae3a -> intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d

As we use target_collection_name in UUIDv5 generation for these objects, the IDs will be different, so this should not cause an issue.

## 6. Sigma Rule Indicator -> CVE Vulnerability

To test this, we will first create a smaller Sigma Rule dataset with a smaller number of CVE entries.

sigma-rules-with-cves.json contains the cves:

* CVE-2023-22518
* CVE-2023-43621
* CVE-2022-26134
* CVE-2021-26084

Which are all found in cve-bundle-for-sigma-rules.json.

First need to remove all the Sigma Rules imported in 5.

```shell
python3 design/mvp/test-helpers/remove-all-collections.py
```

Now import both these files ;

```shell
python3 stix2arango.py	\
	--file design/mvp/tests/sigma-rules-with-cves.json \
	--database cti \
	--collection sigma_rules \
	--ignore_embedded_relationships true && \
python3 stix2arango.py	\
	--file design/mvp/tests/cve-bundle-for-sigma-rules.json \
	--database cti \
	--collection nvd_cve \
	--ignore_embedded_relationships true
```

IMPORTANT NOTE: the objects in the bundle have been modified from their actual versions!

```sql
FOR doc IN sigma_rules_vertex_collection
    FILTER LENGTH(doc.labels) > 0
    FOR label IN doc.labels
        FILTER LEFT(label, 4) == "cve."
        COLLECT cveLabel = label WITH COUNT INTO count
        RETURN { cveLabel, count }
```

Returns a list of all CVE labels that exist. Should return 4 results, each with 1 label. Thus expecting 4 SROs to be create.

```sql
LET cve_ids = [
    "CVE-2023-22518",
    "CVE-2023-43621",
    "CVE-2022-26134",
    "CVE-2021-26084"
]

LET lowercased_cves = (
    FOR id IN cve_ids
        RETURN LOWER(id)
)

LET cve_results = (
	FOR doc IN nvd_cve_vertex_collection
		FILTER doc._stix2arango_note != "automatically imported on collection creation"
        AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
		AND doc.type == "vulnerability"
        AND IS_ARRAY(doc.external_references)
        FOR ext_ref IN doc.external_references
            FILTER LOWER(ext_ref.external_id) IN lowercased_cves
            RETURN { external_id: ext_ref.external_id, doc: doc }
)

RETURN cve_results
```

Should return the 4 results, the CVE Vulnerabilities the Sigma Rule Indicators should be linked to.

As such expected...

4 SRO results expected on first run to be generated by arango_cti_processor


## 8. CVE Indicator -> CPE Software Relationship

```shell
python3 stix2arango.py	\
	--file design/mvp/tests/cpe-bundle-for-cves.json \
	--database cti \
	--collection nvd_cpe \
	--ignore_embedded_relationships true
```

There are 6 `software:cpe=` references inside cve-bundle-for-sigma-rules.json that are covered cpe-bundle-for-cves.json

```sql
FOR doc IN nvd_cve_vertex_collection
    FILTER doc.pattern != NULL
    LET patternText = doc.pattern
    LET initialSplit = SPLIT(SUBSTRING(patternText, 1, LENGTH(patternText) - 2), "') OR ('")
    LET extractedValues = (
        FOR patternPart IN initialSplit
            LET trimmedPart = TRIM(patternPart, "([ ]")
            RETURN trimmedPart
    )
    RETURN {
        "id": doc._key,
        "extractedValues": extractedValues
    }
```

This query will return them all.

* `cpe:2.3:a:atlassian:confluence_server:7.19.9:*:*:*:*:*:*:*`
* `cpe:2.3:a:atlassian:confluence_server:7.19.7:*:*:*:*:*:*:*`
* `cpe:2.3:a:schollz:croc:9.6.5:*:*:*:*:*:*:*`
* `cpe:2.3:a:atlassian:confluence_server:7.17.2:*:*:*:*:*:*:*`
* `cpe:2.3:a:atlassian:confluence_server:7.17.3:*:*:*:*:*:*:*`
* `cpe:2.3:a:atlassian:confluence_server:6.15.0:*:*:*:*:*:*:*`

```sql
FOR doc IN nvd_cpe_vertex_collection
    FILTER doc.type == "software" AND doc.cpe IN ["cpe:2.3:a:atlassian:confluence_server:7.19.9:*:*:*:*:*:*:*", "cpe:2.3:a:atlassian:confluence_server:7.19.7:*:*:*:*:*:*:*", "cpe:2.3:a:schollz:croc:9.6.5:*:*:*:*:*:*:*", "cpe:2.3:a:atlassian:confluence_server:7.17.2:*:*:*:*:*:*:*", "cpe:2.3:a:atlassian:confluence_server:7.17.3:*:*:*:*:*:*:*", "cpe:2.3:a:atlassian:confluence_server:6.15.0:*:*:*:*:*:*:*"]
RETURN [doc]
```

Should return 6 results for the CPEs.

Thus...

6 SRO results expected on first run to be generated by arango_cti_processor

## 9. CVE Vulnerability -> ATT&CK Attack Pattern object

For this test we introduce a fake CVE with clear ATT&CK reference, so we expect the confidence to be high and to create a CVE to ATT&CK link.

The vulnerability object contains the description for T1583 Aquire Infrastructure (https://attack.mitre.org/techniques/T1583/)

```shell
python3 design/mvp/test-helpers/remove-all-collections.py
```

```shell
python3 stix2arango.py	\
	--file design/mvp/tests/fake-cve-with-attack-ref.json \
	--database cti \
	--collection nvd_cve \
	--ignore_embedded_relationships true
```

```sql
FOR doc IN nvd_cve_vertex_collection
	FILTER doc._stix2arango_note != "automatically imported on collection creation"
	RETURN [doc]
```

Should return 2 results, the vulnerability and indicator for a fake CVE; CVE-1988-00000

