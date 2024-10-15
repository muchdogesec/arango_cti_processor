## Sigma Rule Indicator -> CVE Vulnerability (`sigma-cve`)

* Source collection: `sigma_rules_vertex_collection` (`type==indicator` objects only)
* Destination collections: `nvd_cve_vertex_collection` (`type==vulnerability` objects only)

Inside some Indicators for Sigma Rules are `labels` with [CVE tags](https://github.com/SigmaHQ/sigma-specification/blob/main/Tags_specification.md#namespace-cve). e.g.

```json
    "labels": [
        "cve.2021.44228"
    ]
```

The labels identifying CVEs always start with `cve.` followed by the CVE ID where the `-` is replaced with a `.`. e.g. `cve.2021.44228` is refering to CVE-2021-44228.

You can identify the ATT&CK objects listed as follows;

```sql
FOR doc IN nvd_cve_vertex_collection
    FILTER doc.type == "vulnerability"
    AND LENGTH(
        FOR ref IN (doc.external_references != null ? doc.external_references : [])
            FILTER ref.external_id == "<CVE ID>"
            RETURN ref
    ) > 0
    AND doc._stix2arango_note != "automatically imported on collection creation"
    AND doc._is_latest == true
    RETURN doc
```

When a CVE label is identified in a Sigma STIX Indicator object a relationship is created as follows;

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
    "target_ref": "vulnerability--<CVE VULNERABILITY STIX OBJECT>",
    "description": "<SIGMA RULE NAME> <relationship_type without - char> <CVE name>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ]
}
```

To generate the id of SRO, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `relationship_type+source_collection_name/source_ref+target_collection_name/target_ref`  values.

All generated objects are stored in the source edge collection.

You should also use add the arango internal property `_arango_cti_processor_note` == `sigma-cve`