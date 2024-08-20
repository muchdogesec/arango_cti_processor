## CAPEC Attack Pattern -> CWE Weakness relationship (`capec-cwe`)

* Source collection: `mitre_capec_vertex_collection` (`type==attack-pattern` objects only)
* Destination collections: `mitre_cwe_vertex_collection` (`type==weakness` objects only)

At ingest, the code searches for all CWE objects referenced in CAPEC objects (where `"source_name": "cwe"` is present in CAPEC Object).

Take CAPEC-600;

```json
            "external_references": [
                {
                    "external_id": "CAPEC-600",
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/600.html"
                },
                {
                    "external_id": "CWE-522",
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/522.html"
                },
                {
                    "external_id": "CWE-307",
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/307.html"
                },
                {
                    "external_id": "CWE-308",
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/308.html"
                },
                {
                    "external_id": "CWE-309",
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/309.html"
                },
                {
                    "external_id": "CWE-262",
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/262.html"
                },
                {
                    "external_id": "CWE-263",
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/263.html"
                },
                {
                    "external_id": "CWE-654",
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/654.html"
                },
                {
                    "description": "Brute Force:Credential Stuffing",
                    "external_id": "T1110.004",
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/wiki/Technique/T1110/004"
                },
                {
                    "description": "Credential stuffing",
                    "source_name": "OWASP Attacks",
                    "url": "https://owasp.org/www-community/attacks/Credential_stuffing"
                },
                {
                    "description": "Alert (TA18-086A): Brute Force Attacks Conducted by Cyber Actors, 2018--03---27, Cybersecurity and Infrastructure Security Agency (CISA)",
                    "external_id": "REF-567",
                    "source_name": "reference_from_CAPEC",
                    "url": "https://www.us-cert.gov/ncas/alerts/TA18-086A"
                },
                {
                    "description": "Credential stuffing, Open Web Application Security Project (OWASP)",
                    "external_id": "REF-568",
                    "source_name": "reference_from_CAPEC",
                    "url": "https://owasp.org/www-community/attacks/Credential_stuffing"
                },
                {
                    "description": "Jessica Silver-Greenberg, Matthew Goldstein, Nicole Perlroth, JPMorgan Chase Hacking Affects 76 Million Households, 2014--10---02, The New York Times",
                    "external_id": "REF-569",
                    "source_name": "reference_from_CAPEC",
                    "url": "https://dealbook.nytimes.com/2014/10/02/jpmorgan-discovers-further-cyber-security-issues/"
                }
            ],
```

Here, 7 CWE IDs are listed.

You can find a list of all CWE Objects referenced in CAPEC objects using the following search;

```sql
FOR doc IN mitre_capec_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc.type == "attack-pattern"
    LET cweReferences = (
        FOR reference IN (IS_ARRAY(doc.external_references) ? doc.external_references : [])
            FILTER reference.source_name == 'cwe'
            AND reference.external_id == 'NVD-CWE-noinfo'
            RETURN reference.external_id
    )
    FILTER LENGTH(cweReferences) > 0
    FOR cweId IN cweReferences
    COLLECT id = cweId WITH COUNT INTO count
    RETURN { id, count }
```

Note, references where `external_references.external_id==NVD-CWE-noinfo` can be ignored as they don't resolve to a cwe.

CWE STIX IDs can be searched as follows;

```sql
LET ids = ["CWEID"]

FOR doc IN mitre_cwe_vertex_collection
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
    "created": "<CAPEC CREATED TIME>",
    "modified": "<CAPEC MODIFIED TIME>",
    "relationship_type": "exploits",
    "source_ref": "attack-pattern--<CAPEC STIX OBJECT ID>",
    "target_ref": "weakness--<CWE STIX OBJECT ID>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ]
}
```

To generate the id of SRO, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `relationship_type+source_collection_name/source_ref+target_collection_name/target_ref`  values.

All generated objects are stored in the source edge collection.