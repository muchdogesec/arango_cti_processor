## Sigma Rule Indicator -> ATT&CK Attack Pattern relationship (`sigma-attack`)

* Source collection: `sigma_rules_vertex_collection` (`type==indicator` objects only)
* Destination collections: `mitre_attack_enterprise_vertex_collection`, `mitre_attack_mobile_vertex_collection`, `mitre_attack_ics_vertex_collection` (`type==attack-pattern` objects only)

Inside some Indicators for Sigma Rules are `labels` with [ATT&CK tags](https://github.com/SigmaHQ/sigma-specification/blob/main/Tags_specification.md#namespace-attack). e.g.

```json
    "labels": [
        "attack.T1055",
        "attack.T1055.011",
        "attack.S0039"
    ]
```

The labels identifying ATT&CKs always start with `attack.` followed by the ATT&CK ID.

You can identify the ATT&CK objects listed as follows;

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

Note, tactics (`x-mitre-tactic`) objects use the name of the object, not the ID, e.g.

```json
    "labels": [
        "attack.credential_access"
    ]
```

In this case you need to search the name field by replacing the `_` with a whitespace and making the first letter of each word upper case, e.g.

```sql
LET enterprise_results = (
    FOR doc IN mitre_attack_enterprise_vertex_collection
        FILTER doc.type == "x-mitre-tactic"
        AND doc._is_latest == true
        AND doc.name == "Credential Access"
        RETURN doc
)
LET ics_results = (
    FOR doc IN mitre_attack_ics_vertex_collection
        FILTER doc.type == "x-mitre-tactic"
        AND doc._is_latest == true
        AND doc.name == "Credential Access"
        RETURN doc
)
LET mobile_results = (
    FOR doc IN mitre_attack_mobile_vertex_collection
        FILTER doc.type == "x-mitre-tactic"
        AND doc._is_latest == true
        AND doc.name == "Credential Access"
        RETURN doc
)

RETURN UNION(enterprise_results, ics_results, mobile_results)
```

When an ATT&CK label is identified in a Sigma STIX Indicator object a relationship is created as follows;

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUID V5 LOGIC>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<indicator.created>",
    "modified": "<indicator.modified>",
    "relationship_type": "detects",
    "source_ref": "indicator--<SIGMA INDICATOR STIX OBJECT>",
    "target_ref": "<ATT&CK STIX OBJECT>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ]
}
```

To generate the id of SRO, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `relationship_type+source_collection_name/source_ref+target_collection_name/target_ref`  values.

All generated objects are stored in the source edge collection.