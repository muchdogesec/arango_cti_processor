## CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

* Source collection: `mitre_capec_vertex_collection` (`type==attack-pattern` objects only)
* Destination collections: `mitre_attack_enterprise_vertex_collection`, `mitre_attack_mobile_vertex_collection`, `mitre_attack_ics_vertex_collection` (`type==attack-pattern` objects only)

At ingest, the code searches for all ATT&CK objects referenced in CAPEC objects (where `"source_name": "mitre-attack"` is present in CAPEC Object).

Take CAPEC-112 as an example;

```json
            "external_references": [
                {
                    "external_id": "CAPEC-112",
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/112.html"
                },
                {
                    "external_id": "CWE-330",
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/330.html"
                },
                {
                    "external_id": "CWE-326",
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/326.html"
                },
                {
                    "external_id": "CWE-521",
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/521.html"
                },
                {
                    "description": "Brute Force",
                    "external_id": "T1110",
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/wiki/Technique/T1110"
                },
                {
                    "description": "Brute Force",
                    "external_id": "11",
                    "source_name": "WASC",
                    "url": "http://projects.webappsec.org/Brute-Force"
                },
                {
                    "description": "Brute force attack",
                    "source_name": "OWASP Attacks",
                    "url": "https://owasp.org/www-community/attacks/Brute_force_attack"
                }
```

For example, `T1110` is the ATT&CK ID referenced in the CAPEC Object.

You can find a list of all ATT&CK Objects referenced in CAPEC objects using the following search;

```sql
RETURN LENGTH(
FOR doc IN mitre_capec_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc.type == "attack-pattern"
    LET attackReferences = (
        FOR reference IN (IS_ARRAY(doc.external_references) ? doc.external_references : [])
            FILTER reference.source_name == 'mitre-attack'
            RETURN reference
    )
    FILTER LENGTH(attackReferences) > 0
    RETURN [doc]
)
```

Searching through the ATT&CK objects, this resolves to the following object `attack-pattern--a93494bb-4b80-4ea1-8695-3236a49916fd.json` that has the same `external_id` property.

The base query for searching ATT&CK IDs in ArangoDB is;

```sql
LET attack_ids = ["<ATTACK IDS>"]

LET lowercased_attack_ids = (
    FOR id IN attack_ids
        RETURN LOWER(id)
)

LET enterprise_results = (
    FOR doc IN mitre_attack_enterprise_vertex_collection
        FILTER doc._stix2arango_note != "automatically imported on collection creation"
        AND doc._is_latest == true
        AND IS_ARRAY(doc.external_references)
        FOR ext_ref IN doc.external_references
            FILTER LOWER(ext_ref.external_id) IN lowercased_attack_ids
            RETURN doc
)

LET ics_results = (
    FOR doc IN mitre_attack_ics_vertex_collection
        FILTER doc._stix2arango_note != "automatically imported on collection creation"
        AND doc._is_latest == true
        AND IS_ARRAY(doc.external_references)
        FOR ext_ref IN doc.external_references
            FILTER LOWER(ext_ref.external_id) IN lowercased_attack_ids
            RETURN doc
)

LET mobile_results = (
    FOR doc IN mitre_attack_mobile_vertex_collection
        FILTER doc._stix2arango_note != "automatically imported on collection creation"
        AND doc._is_latest == true
        AND IS_ARRAY(doc.external_references)
        FOR ext_ref IN doc.external_references
            FILTER LOWER(ext_ref.external_id) IN lowercased_attack_ids
            RETURN doc
)

RETURN UNION(enterprise_results, ics_results, mobile_results)
```

When a match is found, the code will create a STIX 2.1 SRO in the following format;

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUIDV5 GENERATION LOGIC>",
    "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    "created": "<CAPEC CREATED TIME>",
    "modified": "<CAPEC MODIFIED TIME>",
    "relationship_type": "related-to",
    "source_ref": "attack-pattern--<CAPEC STIX OBJECT ID>",
    "target_ref": "attack-pattern--<ATT&CK STIX OBJECT ID>",
    "description": "<CAPEC name> <relationship_type without - char> <ATT&CK name>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "arking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
}
```

To generate the id of SRO, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `relationship_type+source_collection_name/source_ref+target_collection_name/target_ref` values.

So, for example, lets say I had a CAPEC and ATT&CK SDO; `attack-pattern--eede1d7f-028e-48ff-aa88-a18ed68c2132+attack-pattern--613f2e26-407d-48c7-9eca-b8e91df99dc9`.

To generate the ID for the CAPEC->ATT&CK SRO I would use the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and value `technique+mitre_capec_vertex_collection+attack-pattern--eede1d7f-028e-48ff-aa88-a18ed68c2132+mitre_attack_enterprise_vertex_collection+attack-pattern--613f2e26-407d-48c7-9eca-b8e91df99dc9` = `9cbfae8c-860a-5a24-b23a-bf87e463981e` = `relationship--9cbfae8c-860a-5a24-b23a-bf87e463981e`

All generated objects are stored in the source edge collection. Here's an example

```sql
LET relationships = [
    {
        "_key": "relationship--9cbfae8c-860a-5a24-b23a-bf87e463981e",
        "_from": "mitre_capec_vertex_collection/attack-pattern--eede1d7f-028e-48ff-aa88-a18ed68c2132",
        "_to": "mitre_attack_enterprise_vertex_collection/attack-pattern--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "_arango_cti_processor_note": "capec-attack",
        "_record_created": "<DATETIME OBJECT WAS INSERTED IN DB>",
        "_record_modified": "<DATETIME OBJECT WAS LAST MODIFIED IN DB>",
        "_record_md5_hash": "<HASH OF OBJECT>",
        "_is_latest": true,
        "_is_ref": false,
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--9cbfae8c-860a-5a24-b23a-bf87e463981e",
        "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
        "created": "<CAPEC CREATED TIME>",
        "modified": "<CAPEC MODIFIED TIME>",
        "relationship_type": "technique",
        "source_ref": "attack-pattern--eede1d7f-028e-48ff-aa88-a18ed68c2132",
        "target_ref": "attack-pattern--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "description": "<CAPEC name> <relationship_type without - char> <ATT&CK name>",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
        ]
    }
]
FOR relationship IN relationships
INSERT relationship INTO mitre_capec_edge_collection
```