## ATT&CK Attack Pattern -> CAPEC Attack Pattern relationship (`attack-capec`)

* Source collection: `mitre_attack_enterprise_vertex_collection`, `mitre_attack_mobile_vertex_collection`, `mitre_attack_ics_vertex_collection` (`type==attack-pattern` objects only)
* Destination collections: `mitre_capec_vertex_collection` (`type==attack-pattern` objects only)

At ingest, the code searches for all CAPEC objects referenced in ATT&CK objects (where `"source_name": "capec"` is present in ATT&CK Object).

Take T1100;

```json
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1100",
                    "url": "https://attack.mitre.org/techniques/T1100"
                },
                {
                    "external_id": "CAPEC-650",
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/650.html"
                },
                {
                    "url": "https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html",
                    "description": "Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.",
                    "source_name": "Lee 2013"
                },
                {
                    "url": "https://www.us-cert.gov/ncas/alerts/TA15-314A",
                    "description": "US-CERT. (2015, November 13). Compromised Web Servers and Web Shells - Threat Awareness and Guidance. Retrieved June 8, 2016.",
                    "source_name": "US-CERT Alert TA15-314A Web Shells"
                }
            ],
```

Here 1 CAPEC is listed.

This search will return all CAPECs found in ATT&CK objects;

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

Once you have the CAPEC IDs you can find their STIX IDs as follows

```sql
LET ids = ["CAPEC_ID"]

FOR doc IN mitre_capec_vertex_collection
    FILTER LENGTH(doc.external_references) > 0
    FOR ref IN doc.external_references
        FILTER ref.external_id IN ids
        COLLECT id = ref.external_id WITH COUNT INTO count
        RETURN { id, count }
```

When a match is found, the code will create a STIX 2.1 SRO in the following format;

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUIDV5 GENERATION LOGIC>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<ATTACK CREATED TIME>",
    "modified": "<ATTACK MODIFIED TIME>",
    "relationship_type": "relies-on",
    "source_ref": "attack-pattern--<ATTACK STIX OBJECT ID>",
    "target_ref": "attack-pattern--<CAPEC STIX OBJECT ID>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ]
}
```

To generate the id of SRO, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `relationship_type+source_collection_name/source_ref+target_collection_name/target_ref`  values.

All generated objects are stored in the source edge collection.