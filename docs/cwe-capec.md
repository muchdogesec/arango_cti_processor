## CWE Weakness -> CAPEC Attack Pattern relationship (`cwe-capec`)

* Source collection: `mitre_cwe_vertex_collection` (`type==weakness` objects only)
* Destination collections: `mitre_capec_vertex_collection` (`type==attack-pattern` objects only)

At ingest, the code searches for all CAPEC objects referenced in CWE objects (where `"source_name": "capec"` is present in CWE Object).

Take CWE-521;

```json
    "external_references": [
        {
            "source_name": "cwe",
            "external_id": "CWE-521",
            "url": "http://cwe.mitre.org/data/definitions/521.html"
        },
        {
            "source_name": "Michael Howard, David LeBlanc, John Viega",
            "description": "24 Deadly Sins of Software Security"
        },
        {
            "source_name": "NIST",
            "description": "Digital Identity Guidelines (SP 800-63B)",
            "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf"
        },
        {
            "source_name": "OWASP Top Ten 2007",
            "external_id": "A7",
            "description": "Broken Authentication and Session Management"
        },
        {
            "source_name": "OWASP Top Ten 2004",
            "external_id": "A3",
            "description": "Broken Authentication and Session Management"
        },
        {
            "source_name": "capec",
            "external_id": "CAPEC-112",
            "url": "https://capec.mitre.org/data/definitions/112.html"
        },
        {
            "source_name": "capec",
            "external_id": "CAPEC-16",
            "url": "https://capec.mitre.org/data/definitions/16.html"
        },
        {
            "source_name": "capec",
            "external_id": "CAPEC-49",
            "url": "https://capec.mitre.org/data/definitions/49.html"
        },
        {
            "source_name": "capec",
            "external_id": "CAPEC-555",
            "url": "https://capec.mitre.org/data/definitions/555.html"
        },
        {
            "source_name": "capec",
            "external_id": "CAPEC-509",
            "url": "https://capec.mitre.org/data/definitions/509.html"
        },
        {
            "source_name": "capec",
            "external_id": "CAPEC-55",
            "url": "https://capec.mitre.org/data/definitions/55.html"
        },
        {
            "source_name": "capec",
            "external_id": "CAPEC-561",
            "url": "https://capec.mitre.org/data/definitions/561.html"
        },
        {
            "source_name": "capec",
            "external_id": "CAPEC-565",
            "url": "https://capec.mitre.org/data/definitions/565.html"
        },
        {
            "source_name": "capec",
            "external_id": "CAPEC-70",
            "url": "https://capec.mitre.org/data/definitions/70.html"
        }
```

Here, 9 CAPEC IDs are listed. Thus 9 SROs would be created.

To find all CAPECs referenced in CPEs use the following query;

```sql
FOR doc IN mitre_cwe_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
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

To find matching CAPEC STIX IDs for returned results;

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
    "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    "created": "<CWE CREATED TIME>",
    "modified": "<CWE MODIFIED TIME>",
    "relationship_type": "related-to",
    "source_ref": "weakness--<CWE STIX OBJECT ID>",
    "target_ref": "attack-pattern--<CAPEC STIX OBJECT ID>",
    "description": "<CWE name> <relationship_type without - char> <CAPEC name>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "arking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
}
```

To generate the id of SRO, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `relationship_type+source_collection_name/source_ref+target_collection_name/target_ref`  values.

All generated objects are stored in the source edge collection.

You should also use add the arango internal property `_arango_cti_processor_note` == `cwe-capec`