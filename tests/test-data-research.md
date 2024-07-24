# Test data prep

This doc exists to shed some light on the knowledgebase bundles, to understand what data arango_cti_processor should produce...

arango_cti_processor expects the following collections

1. mitre_attack_enterprise_vertex_collection
2. mitre_attack_enterprise_edge_collection
3. mitre_attack_mobile_vertex_collection
4. mitre_attack_mobile_edge_collection
5. mitre_attack_ics_vertex_collection
6. mitre_attack_ics_edge_collection
7. mitre_capec_edge_collection
8. mitre_capec_vertex_collection
9. mitre_cwe_vertex_collection
10. mitre_cwe_edge_collection
11. sigma_rules_vertex_collection
12. sigma_rules_edge_collection
13. nvd_cve_vertex_collection
14. nvd_cve_edge_collection
15. nvd_cpe_vertex_collection
16. nvd_cpe_edge_collection

First, make sure no data exists in them...

Run this command in the arango_cti_processor venv...

```shell
python3 design/mvp/test-helpers/remove-all-collections.py
```

## 1. CAPEC -> ATT&CK

Import the required data...

```shell
python3 stix2arango.py	\
	--file backfill_data/mitre_attack_enterprise/enterprise-attack-v14_1.json \
	--database cti \
	--collection mitre_attack_enterprise \
	--stix2arango_note v14.1 \
	--ignore_embedded_relationships true && \
python3 stix2arango.py	\
	--file backfill_data/mitre_attack_ics/ics-attack-v14_1.json \
	--database cti \
	--collection mitre_attack_ics \
	--stix2arango_note v14.1 \
	--ignore_embedded_relationships true && \
python3 stix2arango.py	\
	--file backfill_data/mitre_attack_mobile/mobile-attack-v14_1.json \
	--database cti \
	--collection mitre_attack_mobile \
	--stix2arango_note v14.1 \
	--ignore_embedded_relationships true && \
python3 stix2arango.py	\
	--file backfill_data/mitre_capec/stix-capec-v3_9.json \
	--database cti \
	--collection mitre_capec \
	--stix2arango_note v3.9 \
	--ignore_embedded_relationships true
```

```sql
RETURN LENGTH(
FOR doc IN mitre_capec_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
  AND doc._is_latest == true
  RETURN [doc]
)
```

Should return 1494 -- number of CAPEC objects.

```sql
FOR doc IN mitre_capec_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
  AND doc._is_latest == true
  COLLECT type = doc.type WITH COUNT INTO typeCount
  RETURN { type, typeCount }
```

Should return 4 results with count of how many ATT&CK objects and type exist;

* `attack-pattern`: 615
* `course-of-action `: 877
* `identity`: 1
* `marking-definition`: 1

Sum = 1494

```sql
RETURN LENGTH(
FOR doc IN mitre_capec_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc.type == "attack-pattern"
    LET attackReferences = (
        FOR reference IN (IS_ARRAY(doc.external_references) ? doc.external_references : [])
            FILTER reference.source_name == 'ATTACK'
            RETURN reference
    )
    FILTER LENGTH(attackReferences) > 0
    RETURN [doc]
)
```

This should return 177 results -- the number of CAPEC objects that have at least 1 `external_references.source_name=ATTACK` reference.

```sql
LET attackReferenceCount = SUM(
    FOR doc IN mitre_capec_vertex_collection
        FILTER doc._stix2arango_note != "automatically imported on collection creation"
        AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
        AND doc.type == "attack-pattern"
        LET attackReferences = (
            FOR reference IN (IS_ARRAY(doc.external_references) ? doc.external_references : [])
                FILTER reference.source_name == 'ATTACK'
                RETURN reference
        )
        RETURN LENGTH(attackReferences)
)
RETURN attackReferenceCount
```
In total (because some objects can multiple ATT&CK references) there are 272 `"source_name": "ATTACK"` references

```sql
FOR doc IN mitre_capec_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc.type == "attack-pattern"
    LET attackReferences = (
        FOR reference IN (IS_ARRAY(doc.external_references) ? doc.external_references : [])
            FILTER reference.source_name == 'ATTACK'
            RETURN reference.external_id
    )
    FILTER LENGTH(attackReferences) > 0
    FOR attackId IN attackReferences
    COLLECT id = attackId WITH COUNT INTO count
    RETURN { id, count }
```

Will return 189 results a count of unique ATT&CK IDs, and how many times the ID appears in the CAPEC bundle. The sum of the count field will add up to 269.

```sql
FOR doc IN mitre_capec_vertex_collection
    FILTER doc.external_references != NULL AND IS_ARRAY(doc.external_references)
    LET attackReferences = (
        FOR ext_ref IN doc.external_references
        FILTER ext_ref.source_name == "ATTACK"
        RETURN ext_ref.external_id
    )
    LET uniqueIds = UNIQUE(attackReferences)
    FILTER LENGTH(attackReferences) > LENGTH(uniqueIds)
    RETURN [doc]
```

The above query identifies CAPEC objects where the same ATT&CK ID is seen. It returns 1 result for CAPEC-571 `attack-pattern--8f91fa23-b5c4-48f1-be6c-99582524f8cc` thus the count of expected results will be minus 1.

```sql
RETURN LENGTH(
  FOR doc IN UNION(
    (FOR d IN mitre_attack_enterprise_vertex_collection RETURN d),
    (FOR d IN mitre_attack_ics_vertex_collection RETURN d),
    (FOR d IN mitre_attack_mobile_vertex_collection RETURN d)
  )
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc._is_latest == true
    RETURN [doc]
)
```

Should return 2715. The number of ATT&CK objects.

```sql
FOR doc IN UNION(
    (FOR d IN mitre_attack_enterprise_vertex_collection RETURN d),
    (FOR d IN mitre_attack_ics_vertex_collection RETURN d),
    (FOR d IN mitre_attack_mobile_vertex_collection RETURN d)
  )
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc._is_latest == true
    COLLECT type = doc.type WITH COUNT INTO typeCount
    RETURN { type, typeCount }
```

Should return 13 elements, with the count of each STIX object type;

* `attack-pattern`: 1043
* `campaign`: 28
* `course-of-action`: 384
* `identity`: 3
* `intrusion-set`: 182
* `malware`: 702
* `marking-definition`: 3
* `tool`: 88
* `x-mitre-asset`: 14
* `x-mitre-collection`: 3
* `x-mitre-data-component`: 160
* `x-mitre-data-source`: 61
* `x-mitre-matrix`: 4
* `x-mitre-tactic`: 40

Sum = 2655

```sql
LET ids = ["T1001.002","T1003","T1005","T1007","T1012","T1014","T1016","T1018","T1021","T1021.002","T1027","T1027.001","T1027.003","T1027.004","T1027.006","T1027.009","T1033","T1036","T1036.001","T1036.003","T1036.004","T1036.005","T1036.006","T1036.007","T1037","T1039","T1040","T1046","T1049","T1052","T1055","T1055.003","T1056","T1056.001","T1056.004","T1057","T1069","T1070","T1072","T1078","T1078.001","T1080","T1082","T1083","T1087","T1090.001","T1090.004","T1091","T1092","T1110","T1110.001","T1110.002","T1110.003","T1110.004","T1111","T1112","T1113","T1114.002","T1115","T1119","T1120","T1123","T1124","T1125","T1127","T1133","T1134","T1134.001","T1134.002","T1134.003","T1135","T1176","T1185","T1195","T1195.001","T1195.002","T1195.003","T1200","T1211","T1213","T1217","T1218.001","T1221","T1491","T1495","T1498.001","T1498.002","T1499","T1499.001","T1499.002","T1499.003","T1499.004","T1505.003","T1505.004","T1505.005","T1513","T1518.001","T1528","T1530","T1531","T1534","T1539","T1542.001","T1542.002","T1542.003","T1543","T1543.001","T1543.003","T1543.004","T1546.001","T1546.004","T1546.008","T1546.016","T1547","T1547.001","T1547.004","T1547.006","T1547.009","T1547.014","T1548","T1548.004","T1550.001","T1550.002","T1550.003","T1550.004","T1552.001","T1552.002","T1552.003","T1552.004","T1552.006","T1553.002","T1553.004","T1554","T1555","T1555.001","T1556","T1556.006","T1557","T1557.002","T1557.003","T1558","T1558.003","T1562.001","T1562.002","T1562.003","T1562.004","T1562.006","T1562.007","T1562.008","T1562.009","T1563","T1564.009","T1565.002","T1566","T1566.001","T1566.002","T1566.003","T1574.001","T1574.002","T1574.004","T1574.005","T1574.006","T1574.007","T1574.008","T1574.009","T1574.010","T1574.011","T1574.013","T1584.002","T1587.001","T1589","T1590","T1592","T1592.002","T1595","T1598","T1598.001","T1598.002","T1598.003","T1599","T1600","T1602","T1606","T1606.001","T1611","T1614","T1615","T1620","T1647"]

FOR doc IN UNION(
    (FOR d IN mitre_attack_enterprise_vertex_collection RETURN d),
    (FOR d IN mitre_attack_ics_vertex_collection RETURN d),
    (FOR d IN mitre_attack_mobile_vertex_collection RETURN d)
  )
    FILTER LENGTH(doc.external_references) > 0
    FOR ref IN doc.external_references
        FILTER ref.external_id IN ids
        COLLECT id = ref.external_id WITH COUNT INTO count
        RETURN { id, count }
```

The list is from the ATT&CK IDs we know exist in CAPEC objects from previous searches.

Should return 189 results, with a count for each. The sum of the count should equal 244.

Using the previous two results (count of ATT&CK refs in CAPECs, and count of ATT&CK objects), we can calculate the number SROs arango_cti_processor should create -- 347 - 1 so...

336 SRO results expected on first run to be generated by arango_cti_processor

## 2. CAPEC Attack Pattern -> CWE Weakness

Import the required data...

```shell
python3 stix2arango.py	\
	--file backfill_data/mitre_cwe/cwe-bundle-4_13.json \
	--database cti \
	--collection mitre_cwe \
	--stix2arango_note v4.13 \
	--ignore_embedded_relationships true
```

```sql
FOR doc IN mitre_capec_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc.type == "attack-pattern"
    LET cweReferences = (
        FOR reference IN (IS_ARRAY(doc.external_references) ? doc.external_references : [])
            FILTER reference.source_name == 'cwe'
            RETURN reference.external_id
    )
    FILTER LENGTH(cweReferences) > 0
    FOR cweId IN cweReferences
    COLLECT id = cweId WITH COUNT INTO count
    RETURN { id, count }
```

Should return 336 elements (number of CWE references). Summing the count field gives 1214.

```sql
FOR doc IN mitre_capec_vertex_collection
    FILTER doc.external_references != NULL AND IS_ARRAY(doc.external_references)
    LET cweReferences = (
        FOR ext_ref IN doc.external_references
        FILTER ext_ref.source_name == "cwe"
        RETURN ext_ref.external_id
    )
    LET uniqueIds = UNIQUE(cweReferences)
    FILTER LENGTH(cweReferences) > LENGTH(uniqueIds)
    RETURN [doc]
```

Looks for objects with duplicate CWE references. Returns 2 results

* CAPEC-545: `attack-pattern--191fbdab-d3b3-4ffd-8829-51331c20eaa7`
* CAPEC-644: `attack-pattern--056a463d-6303-438e-a43f-992cee52fb95`

Thus, -2 result expected to be generated = 1214 - 2 = 1212

```sql
LET ids = [ 
"CWE-1007","CWE-1021","CWE-1037","CWE-112","CWE-113","CWE-114","CWE-116","CWE-117","CWE-118","CWE-1188","CWE-1189","CWE-119","CWE-1190","CWE-1191","CWE-1192","CWE-1193","CWE-120","CWE-1204","CWE-1209","CWE-122","CWE-1220","CWE-1221","CWE-1222","CWE-1223","CWE-1224","CWE-1231","CWE-1232","CWE-1233","CWE-1234","CWE-1239","CWE-1240","CWE-1241","CWE-1242","CWE-1243","CWE-1244","CWE-1245","CWE-1246","CWE-1247","CWE-1248","CWE-125","CWE-1252","CWE-1253","CWE-1254","CWE-1255","CWE-1256","CWE-1257","CWE-1258","CWE-1259","CWE-1260","CWE-1262","CWE-1263","CWE-1264","CWE-1265","CWE-1266","CWE-1267","CWE-1268","CWE-1269","CWE-1270","CWE-1271","CWE-1272","CWE-1273","CWE-1274","CWE-1275","CWE-1277","CWE-1278","CWE-1279","CWE-128","CWE-1280","CWE-1281","CWE-1282","CWE-1283","CWE-1286","CWE-129","CWE-1294","CWE-1295","CWE-1296","CWE-1297","CWE-1298","CWE-1299","CWE-130","CWE-1300","CWE-1301","CWE-1302","CWE-1303","CWE-1304","CWE-131","CWE-1310","CWE-1311","CWE-1312","CWE-1313","CWE-1314","CWE-1315","CWE-1316","CWE-1317","CWE-1318","CWE-1319","CWE-1320","CWE-1321","CWE-1322","CWE-1323","CWE-1325","CWE-1326","CWE-1327","CWE-1328","CWE-1330","CWE-1331","CWE-1332","CWE-1333","CWE-1334","CWE-1338","CWE-134","CWE-1342","CWE-1351","CWE-138","CWE-140","CWE-146","CWE-147","CWE-149","CWE-15","CWE-150","CWE-154","CWE-157","CWE-158","CWE-162","CWE-172","CWE-173","CWE-176","CWE-177","CWE-179","CWE-180","CWE-181","CWE-183","CWE-184","CWE-185","CWE-190","CWE-196","CWE-20","CWE-200","CWE-201","CWE-203","CWE-204","CWE-205","CWE-208","CWE-209","CWE-212","CWE-22","CWE-221","CWE-226","CWE-23","CWE-233","CWE-235","CWE-241","CWE-250","CWE-257","CWE-261","CWE-262","CWE-263","CWE-267","CWE-269","CWE-270","CWE-272","CWE-276","CWE-279","CWE-282","CWE-284","CWE-285","CWE-287","CWE-288","CWE-290","CWE-291","CWE-294","CWE-295","CWE-300","CWE-301","CWE-302","CWE-303","CWE-306","CWE-307","CWE-308","CWE-309","CWE-311","CWE-312","CWE-314","CWE-315","CWE-318","CWE-319","CWE-325","CWE-326","CWE-327","CWE-328","CWE-330","CWE-331","CWE-345","CWE-346","CWE-347","CWE-348","CWE-349","CWE-350","CWE-352","CWE-353","CWE-354","CWE-359","CWE-36","CWE-362","CWE-363","CWE-366","CWE-367","CWE-368","CWE-370","CWE-372","CWE-377","CWE-384","CWE-385","CWE-400","CWE-404","CWE-41","CWE-412","CWE-419","CWE-424","CWE-425","CWE-426","CWE-427","CWE-430","CWE-434","CWE-436","CWE-441","CWE-444","CWE-451","CWE-46","CWE-470","CWE-471","CWE-472","CWE-473","CWE-488","CWE-489","CWE-494","CWE-497","CWE-502","CWE-506","CWE-507","CWE-514","CWE-521","CWE-522","CWE-523","CWE-524","CWE-525","CWE-532","CWE-538","CWE-539","CWE-552","CWE-553","CWE-564","CWE-565","CWE-567","CWE-589","CWE-59","CWE-593","CWE-6","CWE-601","CWE-602","CWE-61","CWE-610","CWE-611","CWE-614","CWE-638","CWE-640","CWE-642","CWE-645","CWE-646","CWE-648","CWE-649","CWE-654","CWE-662","CWE-663","CWE-664","CWE-665","CWE-667","CWE-674","CWE-680","CWE-682","CWE-689","CWE-69","CWE-691","CWE-692","CWE-693","CWE-695","CWE-696","CWE-697","CWE-706","CWE-707","CWE-73","CWE-732","CWE-733","CWE-74","CWE-749","CWE-75","CWE-757","CWE-77","CWE-770","CWE-772","CWE-776","CWE-78","CWE-79","CWE-798","CWE-80","CWE-805","CWE-81","CWE-822","CWE-823","CWE-829","CWE-83","CWE-833","CWE-836","CWE-838","CWE-85","CWE-86","CWE-862","CWE-87","CWE-88","CWE-89","CWE-90","CWE-91","CWE-912","CWE-916","CWE-918","CWE-923","CWE-925","CWE-93","CWE-94","CWE-940","CWE-943","CWE-95","CWE-96","CWE-97","CWE-98","CWE-99"
]

FOR doc IN mitre_cwe_vertex_collection
    FILTER LENGTH(doc.external_references) > 0
    FOR ref IN doc.external_references
        FILTER ref.external_id IN ids
        COLLECT id = ref.external_id WITH COUNT INTO count
        RETURN { id, count }
```

Using the previous data returned we can check all the CWEs exist.

Should return 336 results (meaning all CWE references in CAPEC have 1 object)...

so 1212 SRO results expected on first run to be generated by arango_cti_processor

## 3. CWE Weakness -> CAPEC Attack Pattern

```sql
FOR doc IN mitre_cwe_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc.type == "weakness"
    LET capecReferences = (
        FOR reference IN (IS_ARRAY(doc.external_references) ? doc.external_references : [])
            FILTER reference.source_name == 'capec'
            RETURN reference.external_id
    )
    FILTER LENGTH(capecReferences) > 0
    FOR capecId IN capecReferences
    COLLECT id = capecId WITH COUNT INTO count
    RETURN { id, count }
```

Should return 450 elements (number of CAPEC references). Summing the count field gives 1212.

```sql
FOR doc IN mitre_cwe_vertex_collection
    FILTER doc.external_references != NULL AND IS_ARRAY(doc.external_references)
    AND doc.type == "weakness"
    LET capecReferences = (
        FOR ext_ref IN doc.external_references
        FILTER ext_ref.source_name == "capec"
        RETURN ext_ref.external_id
    )
    LET uniqueIds = UNIQUE(capecReferences)
    FILTER LENGTH(capecReferences) > LENGTH(uniqueIds)
    RETURN [doc]
```

Looks for objects with duplicate CWE references. Returns 0 results.

```sql
LET ids = [
"CAPEC-1","CAPEC-10","CAPEC-100","CAPEC-101","CAPEC-102","CAPEC-103","CAPEC-104","CAPEC-105","CAPEC-107","CAPEC-108","CAPEC-109","CAPEC-11","CAPEC-110","CAPEC-111","CAPEC-112","CAPEC-113","CAPEC-114","CAPEC-115","CAPEC-116","CAPEC-117","CAPEC-12","CAPEC-120","CAPEC-121","CAPEC-122","CAPEC-123","CAPEC-124","CAPEC-125","CAPEC-126","CAPEC-127","CAPEC-128","CAPEC-129","CAPEC-13","CAPEC-130","CAPEC-131","CAPEC-132","CAPEC-133","CAPEC-134","CAPEC-135","CAPEC-136","CAPEC-137","CAPEC-138","CAPEC-139","CAPEC-14","CAPEC-140","CAPEC-141","CAPEC-142","CAPEC-143","CAPEC-144","CAPEC-145","CAPEC-146","CAPEC-147","CAPEC-148","CAPEC-149","CAPEC-15","CAPEC-150","CAPEC-151","CAPEC-153","CAPEC-154","CAPEC-155","CAPEC-157","CAPEC-158","CAPEC-159","CAPEC-16","CAPEC-160","CAPEC-161","CAPEC-162","CAPEC-163","CAPEC-164","CAPEC-166","CAPEC-167","CAPEC-168","CAPEC-169","CAPEC-17","CAPEC-170","CAPEC-173","CAPEC-174","CAPEC-175","CAPEC-176","CAPEC-177","CAPEC-178","CAPEC-18","CAPEC-180","CAPEC-181","CAPEC-182","CAPEC-183","CAPEC-184","CAPEC-185","CAPEC-186","CAPEC-187","CAPEC-188","CAPEC-189","CAPEC-19","CAPEC-190","CAPEC-191","CAPEC-192","CAPEC-193","CAPEC-194","CAPEC-196","CAPEC-197","CAPEC-198","CAPEC-199","CAPEC-2","CAPEC-20","CAPEC-201","CAPEC-202","CAPEC-203","CAPEC-204","CAPEC-206","CAPEC-207","CAPEC-208","CAPEC-209","CAPEC-21","CAPEC-212","CAPEC-215","CAPEC-216","CAPEC-217","CAPEC-218","CAPEC-219","CAPEC-22","CAPEC-220","CAPEC-221","CAPEC-222","CAPEC-224","CAPEC-226","CAPEC-227","CAPEC-228","CAPEC-229","CAPEC-23","CAPEC-230","CAPEC-231","CAPEC-233","CAPEC-234","CAPEC-237","CAPEC-24","CAPEC-240","CAPEC-242","CAPEC-243","CAPEC-244","CAPEC-245","CAPEC-247","CAPEC-248","CAPEC-25","CAPEC-250","CAPEC-251","CAPEC-252","CAPEC-253","CAPEC-256","CAPEC-26","CAPEC-261","CAPEC-263","CAPEC-267","CAPEC-268","CAPEC-27","CAPEC-270","CAPEC-271","CAPEC-273","CAPEC-274","CAPEC-275","CAPEC-276","CAPEC-277","CAPEC-278","CAPEC-279","CAPEC-28","CAPEC-285","CAPEC-287","CAPEC-29","CAPEC-290","CAPEC-291","CAPEC-292","CAPEC-293","CAPEC-294","CAPEC-295","CAPEC-296","CAPEC-297","CAPEC-298","CAPEC-299","CAPEC-3","CAPEC-30","CAPEC-300","CAPEC-301","CAPEC-302","CAPEC-303","CAPEC-304","CAPEC-305","CAPEC-306","CAPEC-307","CAPEC-308","CAPEC-309","CAPEC-31","CAPEC-310","CAPEC-312","CAPEC-313","CAPEC-317","CAPEC-318","CAPEC-319","CAPEC-32","CAPEC-320","CAPEC-321","CAPEC-322","CAPEC-323","CAPEC-324","CAPEC-325","CAPEC-326","CAPEC-327","CAPEC-328","CAPEC-329","CAPEC-33","CAPEC-330","CAPEC-331","CAPEC-332","CAPEC-34","CAPEC-35","CAPEC-36","CAPEC-37","CAPEC-38","CAPEC-383","CAPEC-384","CAPEC-385","CAPEC-386","CAPEC-387","CAPEC-388","CAPEC-389","CAPEC-39","CAPEC-4","CAPEC-40","CAPEC-401","CAPEC-402","CAPEC-41","CAPEC-42","CAPEC-43","CAPEC-439","CAPEC-44","CAPEC-441","CAPEC-442","CAPEC-448","CAPEC-45","CAPEC-456","CAPEC-457","CAPEC-458","CAPEC-459","CAPEC-46","CAPEC-460","CAPEC-461","CAPEC-462","CAPEC-463","CAPEC-464","CAPEC-465","CAPEC-466","CAPEC-467","CAPEC-468","CAPEC-469","CAPEC-47","CAPEC-470","CAPEC-471","CAPEC-472","CAPEC-473","CAPEC-474","CAPEC-475","CAPEC-476","CAPEC-477","CAPEC-478","CAPEC-479","CAPEC-48","CAPEC-480","CAPEC-481","CAPEC-482","CAPEC-485","CAPEC-486","CAPEC-487","CAPEC-488","CAPEC-489","CAPEC-49","CAPEC-490","CAPEC-491","CAPEC-492","CAPEC-493","CAPEC-494","CAPEC-495","CAPEC-496","CAPEC-497","CAPEC-498","CAPEC-499","CAPEC-5","CAPEC-50","CAPEC-500","CAPEC-501","CAPEC-502","CAPEC-503","CAPEC-504","CAPEC-506","CAPEC-508","CAPEC-509","CAPEC-51","CAPEC-510","CAPEC-52","CAPEC-528","CAPEC-53","CAPEC-533","CAPEC-536","CAPEC-538","CAPEC-54","CAPEC-540","CAPEC-541","CAPEC-545","CAPEC-546","CAPEC-549","CAPEC-55","CAPEC-550","CAPEC-551","CAPEC-552","CAPEC-554","CAPEC-555","CAPEC-556","CAPEC-558","CAPEC-560","CAPEC-561","CAPEC-562","CAPEC-563","CAPEC-564","CAPEC-565","CAPEC-57","CAPEC-573","CAPEC-574","CAPEC-575","CAPEC-576","CAPEC-577","CAPEC-578","CAPEC-579","CAPEC-58","CAPEC-580","CAPEC-586","CAPEC-587","CAPEC-588","CAPEC-589","CAPEC-59","CAPEC-590","CAPEC-591","CAPEC-592","CAPEC-593","CAPEC-594","CAPEC-595","CAPEC-596","CAPEC-597","CAPEC-6","CAPEC-60","CAPEC-600","CAPEC-606","CAPEC-608","CAPEC-609","CAPEC-61","CAPEC-612","CAPEC-613","CAPEC-614","CAPEC-615","CAPEC-616","CAPEC-618","CAPEC-619","CAPEC-62","CAPEC-620","CAPEC-621","CAPEC-622","CAPEC-623","CAPEC-624","CAPEC-625","CAPEC-63","CAPEC-632","CAPEC-633","CAPEC-634","CAPEC-635","CAPEC-636","CAPEC-637","CAPEC-639","CAPEC-64","CAPEC-640","CAPEC-641","CAPEC-642","CAPEC-643","CAPEC-644","CAPEC-645","CAPEC-646","CAPEC-647","CAPEC-648","CAPEC-649","CAPEC-65","CAPEC-650","CAPEC-651","CAPEC-652","CAPEC-653","CAPEC-654","CAPEC-657","CAPEC-66","CAPEC-660","CAPEC-661","CAPEC-662","CAPEC-663","CAPEC-664","CAPEC-665","CAPEC-666","CAPEC-667","CAPEC-668","CAPEC-67","CAPEC-675","CAPEC-676","CAPEC-679","CAPEC-68","CAPEC-680","CAPEC-681","CAPEC-682","CAPEC-69","CAPEC-691","CAPEC-692","CAPEC-693","CAPEC-694","CAPEC-695","CAPEC-696","CAPEC-697","CAPEC-698","CAPEC-699","CAPEC-7","CAPEC-70","CAPEC-701","CAPEC-702","CAPEC-71","CAPEC-72","CAPEC-73","CAPEC-74","CAPEC-75","CAPEC-76","CAPEC-77","CAPEC-78","CAPEC-79","CAPEC-8","CAPEC-80","CAPEC-81","CAPEC-83","CAPEC-84","CAPEC-85","CAPEC-86","CAPEC-87","CAPEC-88","CAPEC-89","CAPEC-9","CAPEC-90","CAPEC-92","CAPEC-93","CAPEC-94","CAPEC-95","CAPEC-96","CAPEC-97","CAPEC-98"
]

FOR doc IN mitre_capec_vertex_collection
    FILTER LENGTH(doc.external_references) > 0
    FOR ref IN doc.external_references
        FILTER ref.external_id IN ids
        COLLECT id = ref.external_id WITH COUNT INTO count
        RETURN { id, count }
```

Using the previous data returned we can check all the CAPECS exist.

Should return 450 results (meaning all CAPEC references in CWE have 1 object) so...

1212 SRO results expected on first run to be generated by arango_cti_processor

## 4. ATT&CK Attack Pattern -> CAPEC Attack Pattern

```sql
FOR doc IN UNION(
  (FOR d IN mitre_attack_enterprise_vertex_collection RETURN d),
  (FOR d IN mitre_attack_ics_vertex_collection RETURN d),
  (FOR d IN mitre_attack_mobile_vertex_collection RETURN d)
)
    FILTER doc._stix2arango_note IN ["v14.1", "automatically imported on collection creation"]
    LET capecReferences = (
        FOR reference IN (IS_ARRAY(doc.external_references) ? doc.external_references : [])
            FILTER reference.source_name == 'capec'
            RETURN reference.external_id
    )
    FILTER LENGTH(capecReferences) > 0
    FOR capecId IN capecReferences
    COLLECT id = capecId WITH COUNT INTO count
    RETURN { id, count }
```

Should return 32 unique CAPEC IDs. The sum of the count should be 36 -- the number of SROs to be created by arango_cti_processor.

```sql
FOR doc IN UNION(
  (FOR d IN mitre_attack_enterprise_vertex_collection RETURN d),
  (FOR d IN mitre_attack_ics_vertex_collection RETURN d),
  (FOR d IN mitre_attack_mobile_vertex_collection RETURN d)
)
    FILTER doc.external_references != NULL AND IS_ARRAY(doc.external_references)
    LET capecReferences = (
        FOR ext_ref IN doc.external_references
        FILTER ext_ref.source_name == "capec"
        RETURN ext_ref.external_id
    )
    LET uniqueIds = UNIQUE(capecReferences)
    FILTER LENGTH(capecReferences) > LENGTH(uniqueIds)
    RETURN [doc]
```

Looks for objects with duplicate CWE references. Returns 0 results.

```sql
LET ids = [
"CAPEC-13","CAPEC-132","CAPEC-159","CAPEC-163","CAPEC-17","CAPEC-187","CAPEC-270","CAPEC-471","CAPEC-478","CAPEC-479","CAPEC-532","CAPEC-550","CAPEC-551","CAPEC-552","CAPEC-555","CAPEC-556","CAPEC-558","CAPEC-561","CAPEC-563","CAPEC-564","CAPEC-569","CAPEC-570","CAPEC-571","CAPEC-572","CAPEC-578","CAPEC-579","CAPEC-639","CAPEC-641","CAPEC-644","CAPEC-645","CAPEC-649","CAPEC-650"
]
FOR doc IN mitre_capec_vertex_collection
    FILTER LENGTH(doc.external_references) > 0
    FOR ref IN doc.external_references
        FILTER ref.external_id IN ids
        COLLECT id = ref.external_id WITH COUNT INTO count
        RETURN { id, count }
```

Using the list of CAPECs previously we can check all CAPEC objects actually exist.

Returns 32 CAPECS which means all references in ATT&CK resolve to a CAPEC so...

36 SRO results expected on first run to be generated by arango_cti_processor

## 5. Sigma Rule Indicator -> ATT&CK Attack Pattern

Import the required data...

```shell
python3 stix2arango.py	\
	--file backfill_data/sigma_rules/sigma-rule-bundle.json \
	--database cti \
	--collection sigma_rules \
	--ignore_embedded_relationships true
```

```sql
FOR doc IN sigma_rules_vertex_collection
    FILTER LENGTH(doc.labels) > 0
    FOR label IN doc.labels
        FILTER LEFT(label, 7) == "attack."
        COLLECT attackLabel = label WITH COUNT INTO count
        RETURN { attackLabel, count }
```

Returns a list of all ATT&CK labels that exist. Should return 408 unique IDs. The sum of the count field should be 7376 (labels in total)

```sql
FOR doc IN sigma_rules_vertex_collection
    FILTER LENGTH(doc.labels) > 0
    LET attackLabels = (
        FOR label IN doc.labels
            FILTER LEFT(label, 7) == "attack."
            COLLECT l = label WITH COUNT INTO count
            FILTER count > 1
            RETURN l
    )
    FILTER LENGTH(attackLabels) > 0
    RETURN { doc, duplicateLabels: attackLabels }
```

Identifies objects with duplicate attack labels. Should be 0.

```sql
LET attack_ids = ["g0010","g0020","g0022","g0032","g0044","g0046","g0047","g0049","g0060","g0069","g0080","g0091","g0093","g0125","s0002","s0005","s0029","s0039","s0040","s0075","s0106","s0108","s0111","s0139","s0154","s0190","s0195","s0246","s0349","s0363","s0402","s0404","s0482","s0508","s0575","s0592","t1001.003","t1003","t1003.001","t1003.002","t1003.003","t1003.004","t1003.005","t1003.006","t1005","t1007","t1008","t1010","t1012","t1014","t1016","t1018","t1020","t1021","t1021.001","t1021.002","t1021.003","t1021.004","t1021.005","t1021.006","t1027","t1027.001","t1027.002","t1027.003","t1027.004","t1027.005","t1027.009","t1027.010","t1030","t1033","t1036","t1036.002","t1036.003","t1036.004","t1036.005","t1036.006","t1036.007","t1037.001","t1037.005","t1039","t1040","t1041","t1046","t1047","t1048","t1048.001","t1048.003","t1049","t1053","t1053.002","t1053.003","t1053.005","t1055","t1055.001","t1055.003","t1055.009","t1055.012","t1056","t1056.001","t1056.002","t1057","t1059","t1059.001","t1059.002","t1059.003","t1059.004","t1059.005","t1059.006","t1059.007","t1059.009","t1068","t1069","t1069.001","t1069.002","t1070","t1070.001","t1070.002","t1070.003","t1070.004","t1070.005","t1070.006","t1070.008","t1071","t1071.001","t1071.004","t1072","t1074","t1074.001","t1078","t1078.001","t1078.002","t1078.003","t1078.004","t1082","t1083","t1087","t1087.001","t1087.002","t1087.004","t1090","t1090.001","t1090.002","t1090.003","t1091","t1095","t1098","t1098.001","t1098.003","t1102","t1102.001","t1102.002","t1102.003","t1104","t1105","t1106","t1110","t1110.001","t1110.002","t1112","t1113","t1114","t1114.001","t1115","t1119","t1120","t1123","t1124","t1125","t1127","t1127.001","t1132.001","t1133","t1134","t1134.001","t1134.002","t1134.003","t1134.004","t1134.005","t1135","t1136","t1136.001","t1136.002","t1136.003","t1137","t1137.002","t1137.003","t1137.006","t1140","t1176","t1185","t1187","t1189","t1190","t1195","t1195.001","t1197","t1199","t1200","t1201","t1202","t1203","t1204","t1204.001","t1204.002","t1207","t1210","t1211","t1212","t1213.003","t1216","t1216.001","t1217","t1218","t1218.001","t1218.002","t1218.003","t1218.005","t1218.007","t1218.008","t1218.009","t1218.010","t1218.011","t1218.013","t1219","t1220","t1221","t1222","t1222.001","t1222.002","t1482","t1484","t1484.001","t1485","t1486","t1489","t1490","t1491.001","t1495","t1496","t1497.001","t1499.004","t1505","t1505.002","t1505.003","t1505.004","t1505.005","t1518","t1518.001","t1525","t1526","t1528","t1529","t1531","t1537","t1539","t1542.001","t1542.003","t1543","t1543.001","t1543.002","t1543.003","t1543.004","t1546","t1546.001","t1546.002","t1546.003","t1546.004","t1546.007","t1546.008","t1546.009","t1546.010","t1546.011","t1546.012","t1546.013","t1546.014","t1546.015","t1547","t1547.001","t1547.002","t1547.003","t1547.004","t1547.005","t1547.006","t1547.008","t1547.009","t1547.010","t1547.014","t1547.015","t1548","t1548.001","t1548.002","t1548.003","t1550","t1550.001","t1550.002","t1550.003","t1552","t1552.001","t1552.002","t1552.003","t1552.004","t1552.006","t1552.007","t1553","t1553.001","t1553.002","t1553.003","t1553.004","t1553.005","t1554","t1555","t1555.001","t1555.003","t1555.004","t1555.005","t1556","t1556.002","t1556.006","t1557","t1557.001","t1558","t1558.003","t1559.001","t1559.002","t1560","t1560.001","t1561.001","t1561.002","t1562","t1562.001","t1562.002","t1562.003","t1562.004","t1562.006","t1562.007","t1562.010","t1563.002","t1564","t1564.001","t1564.002","t1564.003","t1564.004","t1564.006","t1565","t1565.001","t1565.002","t1566","t1566.001","t1566.002","t1567","t1567.001","t1567.002","t1568","t1568.002","t1569","t1569.002","t1570","t1571","t1572","t1573","t1574","t1574.001","t1574.002","t1574.005","t1574.006","t1574.007","t1574.008","t1574.011","t1574.012","t1578","t1578.003","t1580","t1584","t1586.003","t1587","t1587.001","t1588","t1588.002","t1589","t1590","t1590.001","t1590.002","t1592.004","t1593.003","t1595.002","t1599.001","t1606","t1608","t1614.001","t1615","t1620","t1621","t1622","t1649"]

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
    RETURN { external_id: id, count }
```

Should return 394 results (number of items in list) and count of how many ATT&CK tactic objects have this id (sum is 474 in total). Multiplying number of labels by count gives: 4401.

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

Should return 14 results (number of items in list) and count of how many ATT&CK tactic objects have this name (sum is 35 in total). Multiplying number of labels by count gives: 10036

4401 + 10036

14437 SRO results expected on first run to be generated by arango_cti_processor

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

## 7. CVE Vulnerability -> CWE Weakness Relationship

```shell
python3 stix2arango.py  \
    --file backfill_data/mitre_cwe/cwe-bundle-4_13.json \
    --database cti \
    --collection mitre_cwe \
    --stix2arango_note v4.13 \
    --ignore_embedded_relationships true
```

```sql
FOR doc IN nvd_cve_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc.type == "vulnerability"
    LET cweReferences = (
        FOR reference IN (IS_ARRAY(doc.external_references) ? doc.external_references : [])
            FILTER reference.source_name == 'cwe'
            AND reference.external_id != "NVD-CWE-noinfo"
            RETURN reference.external_id
    )
    FILTER LENGTH(cweReferences) > 0
    FOR cweId IN cweReferences
    COLLECT id = cweId WITH COUNT INTO count
    RETURN { id, count }

```

Should return 2 results with a count of 4, one CVE has CWE-863 (twice), two CVEs have CWE-917.

Note, because CWE-863 is duplicated in CVE-2023-22518, it should only create one SRO.

```sql
LET ids = [ 
"CWE-863","CWE-917"
]

FOR doc IN mitre_cwe_vertex_collection
    FILTER LENGTH(doc.external_references) > 0
    FOR ref IN doc.external_references
        FILTER ref.external_id IN ids
        COLLECT id = ref.external_id WITH COUNT INTO count
        RETURN { id, count }
```

Should return two results, only two CWEs exist for these IDs.

Thus 4 - 1 =

3 SRO results expected on first run to be generated by arango_cti_processor

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

## 10. CPE Groupings

```shell
python3 design/mvp/test-helpers/remove-all-collections.py
```

```shell
python3 stix2arango.py	\
	--file design/mvp/tests/sample-cpe-bundle.json \
	--database cti \
	--collection nvd_cpe \
	--ignore_embedded_relationships true
```

```sql
FOR doc IN nvd_cpe_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc.type == "software"
    RETURN [doc]
```

Should return 223 results -- the number of software objects in the bundle.

```sql
FOR doc IN nvd_cpe_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
  AND doc.type == "software"
  LET cpe_parts = SPLIT(doc.cpe, ":")
  RETURN {
    "cpe": cpe_parts[0],
    "version": cpe_parts[1],
    "part": cpe_parts[2],
    "vendor": cpe_parts[3],
    "product": cpe_parts[4],
    "version": cpe_parts[5],
    "update": cpe_parts[6],
    "edition": cpe_parts[7],
    "language": cpe_parts[8],
    "sw_edition": cpe_parts[9],
    "target_sw": cpe_parts[10],
    "target_hw": cpe_parts[11],
    "other": cpe_parts[12]
  }
```

Will show a table of the CPE property split out by its part. Should return 223 entries.

```sql
FOR doc IN nvd_cpe_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
  AND doc.type == "software"
  LET cpe_parts = SPLIT(doc.cpe, ":")
  LET vendor = cpe_parts[3]
  COLLECT vendorCount = vendor WITH COUNT INTO count
  RETURN { vendor: vendorCount, count }
```

Should return 175 entries -- showing that some vendors have more than one CPE linked to them. The sum of the columns should be 223.

```sql
FOR doc IN nvd_cpe_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
  AND doc.type == "software"
  LET cpe_parts = SPLIT(doc.cpe, ":")
  LET product = cpe_parts[4]
  COLLECT productCount = product WITH COUNT INTO count
  RETURN { product: productCount, count }
```

Should return 202 entries -- showing that some product have more than one CPE linked to them. The sum of the columns should be 223.

## 11. CPE Groupings (large import)

```shell
python3 design/mvp/test-helpers/remove-all-collections.py
```

```shell
python3 stix2arango.py  \
  --file backfill_data/nvd_cpe/cpe-bundle-2022.json \
  --database cti \
  --collection nvd_cpe \
  --ignore_embedded_relationships true
```

```sql
RETURN LENGTH(
    FOR doc IN nvd_cpe_vertex_collection
        FILTER doc._stix2arango_note != "automatically imported on collection creation"
        AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
        AND doc.type == "software"
        RETURN [doc]
)
```

Should return 178,063 results

```sql
FOR doc IN nvd_cpe_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
  AND doc.type == "software"
  LET cpe_parts = SPLIT(doc.cpe, ":")
  LIMIT @offset, @count
  RETURN {
    "cpe": cpe_parts[0],
    "version": cpe_parts[1],
    "part": cpe_parts[2],
    "vendor": cpe_parts[3],
    "product": cpe_parts[4],
    "version": cpe_parts[5],
    "update": cpe_parts[6],
    "edition": cpe_parts[7],
    "language": cpe_parts[8],
    "sw_edition": cpe_parts[9],
    "target_sw": cpe_parts[10],
    "target_hw": cpe_parts[11],
    "other": cpe_parts[12]
  }
```

Will return the first 1000 results. Need to modify count an offset values to paginate until < 1000 results are returned (indicating no more pages).

```json
{
  "offset": 0,
  "count": 1000
}
```

then 

```json
{
  "offset": 0,
  "count": 1000
}
```

etc.

```sql
LET uniqueVendors = (
  FOR doc IN nvd_cpe_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc.type == "software"
    LET cpe_parts = SPLIT(doc.cpe, ":")
    LET vendor = cpe_parts[3]
    COLLECT uniqueVendor = vendor WITH COUNT INTO length
    RETURN uniqueVendor
)

RETURN LENGTH(uniqueVendors)
```

Returns 3982 unique vendors -- the number of vendor objects expected to be produced.

```sql
LET uniqueVendorProducts = (
  FOR doc IN nvd_cpe_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc._arango_cti_processor_note != "automatically imported object at script runtime"
    AND doc.type == "software"
    LET cpe_parts = SPLIT(doc.cpe, ":")
    LET vendor = cpe_parts[3]
    LET product = cpe_parts[4]
    COLLECT vendorProduct = CONCAT(vendor, ":", product) WITH COUNT INTO length
    RETURN vendorProduct
)

RETURN LENGTH(uniqueVendorProducts)
```

Returns unique vendor/product combinations -- 21650, the number of product objects expected to be created.