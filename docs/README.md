## The logic

### Default STIX objects

To support the generation of relationship, ArangoDB CTI Processor checks the following objects exist in the database, and if they do not adds the following objects to each vertex collection related to the import.

The following objects are automatically inserted (if they do not exist) to each vertex collection on script run (e.g. if running `capec-attack`, then the objects will be stored in `mitre_capec_vertex_collection`).

* Identity: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/arango_cti_processor.json
* Marking Definition: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/arango_cti_processor.json

When imported these objects always have the following Arango custom properties added to them:

* `_arango_cti_processor_note`: `automatically imported object at script runtime`
* `_record_created`: time of collection creation
* `_record_modified`: time of collection creation
* `_record_md5_hash`: hash of object
* `_is_latest`: `true`

They are added as follows;

```sql
LET default_objects = [
    {
        "_key": "<THE OBJECTS STIX ID>",
        "_arango_cti_processor_note": "automatically imported object at script runtime",
        "_record_created": "<DATETIME OBJECT WAS INSERTED IN DB>",
        "_record_modified": "<DATETIME OBJECT WAS INSERTED IN DB>",
        "_record_md5_hash": "<HASH OF OBJECT>",
        "_is_latest": true,
        "<STIX DEFAULT OBJECT>"
    }
]
FOR default_object IN default_objects
INSERT default_object INTO <SOURCE>_vertex_collection
```

### How objects are joined

Note, relationships will cross collections. A created relationship will always be stored in the source object edge collections.

For example, if a relationship between an object in the `mitre_capec_vertex_collection` to another object in the `mitre_attack_enterprise_vertex_collection`, the relationship will be created in the `mitre_capec_edge_collection`

At a high-level the data in CTI Butler is joined follows:

1. CAPEC (`attack-pattern`) -> ATT&CK (`attack-pattern`) [`technique`]
2. CAPEC (`attack-pattern`) -> CWE (`weakness`) [`exploits`]
3. CWE (`weakness`) -> CAPEC (`attack-pattern`) [`exploited-using`]
4. ATT&CK (`attack-pattern`) -> CAPEC (`attack-pattern`) [`relies-on`]
5. Sigma Rule (`indicator`) -> ATT&CK (`attack-pattern`) [`detects`]
6. Sigma Rule (`indicator`) -> CVE (`vulnerability`) [`detects`]
7. CVE (`vulnerability`) -> CWE (`weakness`) [`exploited-using`]
8. CVE (`indicator`) -> CPE (`software`) [`pattern-contains`]
9. CVE (`vulnerability`) -> ATT&CK (`attack-pattern`) [`technique-used`]

The parenthesis (`()`) in the list above denote the STIX Object types in each knowledge-base that are used as the `source_ref` and `target_ref` used to create the joins. The square brackets (`[]`) define the STIX `relationship_type` used in the relationship object used to link them.

Note, all SROs created are added to the respective ArangoDB Collection with the following data;

```sql
LET relationships = [
    {
        "_key": "<THE OBJECTS STIX ID>",
        "_from": "<COLLECTION NAME>/<OBJECTS SOURCE_REF>",
        "_to": "<COLLECTION NAME>/<OBJECTS TARGET_REF>",
        "_arango_cti_processor_note": "<RELATIONSHIP LINK>",
        "_record_created": "<DATETIME OBJECT WAS INSERTED IN DB>",
        "_record_modified": "<DATETIME OBJECT WAS LAST MODIFIED IN DB>",
        "_record_md5_hash": "<HASH OF OBJECT>",
        "_is_latest": true,
        "_is_ref": false,
        "<STIX Relationship OBJECT PROPERTIES>"
    }
]
FOR relationship IN relationships
INSERT relationship INTO <SOURCE>_edge_collection
```

Where:

* `_key`: for new objects, the ID of the STIX object, e.g. `relationship--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f`
* `_arango_cti_processor_note`: Used to identify objects processed by Arango CTI Processor. Shows the link between objects (e.g `capec-attack`)
* `_record_created`: the datetime the object was inserted into the database (e.g. `2020-01-01T01:00:00.000Z`)
* `_record_modified`: the datetime the object was last updated (e.g. `2020-01-01T01:00:00.000Z`). Note, for new objects this always matches the `_record_created` time
* `_record_md5_hash` is an MD5 hash of the STIX objects and the `_arango_cti_processor_note` field. This is used to detect updates to objects.
* `is_latest`: boolean, for newly inserted objects will always be `true`. See update logic to understand why.
* `_is_ref`: boolean, denotes if object was created by a ref or refs property insides a STIX object (see refs section). Will always be `false` for created SROs.

#### 1. CAPEC Attack Pattern -> ATT&CK Attack Pattern relationship (`capec-attack`)

* Source collection: `mitre_capec_vertex_collection` (`type==attack-pattern` objects only)
* Destination collections: `mitre_attack_enterprise_vertex_collection`, `mitre_attack_mobile_vertex_collection`, `mitre_attack_ics_vertex_collection` (`type==attack-pattern` objects only)

At ingest, the code searches for all ATT&CK objects referenced in CAPEC objects (where `"source_name": "ATTACK"` is present in CAPEC Object).

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
                    "source_name": "ATTACK",
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
            FILTER reference.source_name == 'ATTACK'
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
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<CAPEC CREATED TIME>",
    "modified": "<CAPEC MODIFIED TIME>",
    "relationship_type": "technique",
    "source_ref": "attack-pattern--<CAPEC STIX OBJECT ID>",
    "target_ref": "attack-pattern--<ATT&CK STIX OBJECT ID>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
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
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
        ]
    }
]
FOR relationship IN relationships
INSERT relationship INTO mitre_capec_edge_collection
```

#### 2. CAPEC Attack Pattern -> CWE Weakness relationship (`capec-cwe`)

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
                    "source_name": "ATTACK",
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

#### 3. CWE Weakness -> CAPEC Attack Pattern relationship (`cwe-capec`)

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
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<CWE CREATED TIME>",
    "modified": "<CWE MODIFIED TIME>",
    "relationship_type": "exploited-using",
    "source_ref": "weakness--<CWE STIX OBJECT ID>",
    "target_ref": "attack-pattern--<CAPEC STIX OBJECT ID>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ]
}
```

To generate the id of SRO, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `relationship_type+source_collection_name/source_ref+target_collection_name/target_ref`  values.

All generated objects are stored in the source edge collection.

#### 4. ATT&CK Attack Pattern -> CAPEC Attack Pattern relationship (`attack-capec`)

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

#### 5. CVE Vulnerability -> CWE Weakness Relationship (`cve-cwe`)

* Source collection: `nvd_cve_vertex_collection` (`type==vulnerability` objects only)
* Destination collections: `mitre_cwe_vertex_collection` (`type==weakness` objects only)

CWE's are referenced inside the `external_references.external_id` of a CVE vulnerability (`vulnerability`). e.g.

```json
    "external_references": [
        {
            "source_name": "cve",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-6535",
            "external_id": "CVE-2019-6535"
        },
        {
            "source_name": "cwe",
            "url": "https://cwe.mitre.org/data/definitions/CWE-400.html",
            "external_id": "CWE-400"
        },
        {
            "source_name": "cwe",
            "url": "https://cwe.mitre.org/data/definitions/CWE-400.html",
            "external_id": "CWE-400"
        },
        {
            "source_name": "ics-cert@hq.dhs.gov",
            "description": "Third Party Advisory,VDB Entry",
            "url": "http://www.securityfocus.com/bid/106771"
        },
```

You can find a list of all CWE Objects referenced in CVE objects using the following search;

```sql
FOR doc IN nvd_cve_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc.type == "vulnerability"
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

When a CWE is referenced in a CVE Vulnerability object a Relationship Object joins them with the following structure.

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUIDV5 GENERATION LOGIC>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<vulnerabilities.cve.published>",
    "modified": "<vulnerabilities.cve.lastModifiedDate>",
    "relationship_type": "exploited-using",
    "source_ref": "vulnerability--<CVE VULNERABILITY OBJECT>",
    "target_ref": "weakness--<CWE VULNERABILITY OBJECT>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ]
}
```

To generate the id of SRO, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `relationship_type+source_collection_name/source_ref+target_collection_name/target_ref`  values.

All generated objects are stored in the source edge collection.

#### 6. CVE Indicator -> CPE Software Relationship (`cve-cpe`)

* Source collection: `nvd_cve_vertex_collection` (`type==vulnerability` objects only)
* Destination collections: `nvd_cpe_vertex_collection` (`type==software` objects only)

The `pattern` property inside the Indicator SDO contains one or more CPE URIs. 

For example, the pattern part of a CVE Vulnerability object;

```json
"pattern": "([(software:cpe='cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*')]) OR ([(software:cpe='cpe:2.3:o:debian:debian_linux:8.0:*:*:*:*:*:*:*') OR (software:cpe='cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*')]) OR ([(software:cpe='cpe:2.3:o:vmware:esxi:6.0:*:*:*:*:*:*:*')"
```

Contains 4 CPEs.

The corresponding STIX objects for thes CPEs can be identified as follows;

```sql
FOR doc IN nvd_cpe_vertex_collection
    FILTER doc.cpe IN [
        "LIST OF CPES TO IDENFITY"
    ]
    AND doc._stix2arango_note != "automatically imported on collection creation"
    AND doc._is_latest == true
    RETURN doc
```

e.g.

```sql
FOR doc IN nvd_cpe_vertex_collection
    FILTER doc.cpe IN [
        "cpe:2.3:a:sha2_project:sha2:0.4.1:*:*:*:*:rust:*:*"
    ]
    AND doc._stix2arango_note != "automatically imported on collection creation"
    AND doc._is_latest == true
    RETURN doc
```

For every CPE URI inside a pattern, a relationship between the Indicator and corresponding Software object is made and represented as follows;

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUID V5 LOGIC>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<vulnerabilities.cve.published>",
    "modified": "<vulnerabilities.cve.lastModifiedDate>",
    "relationship_type": "pattern-contains",
    "source_ref": "indicator--<INDICATOR STIX OBJECT>",
    "target_ref": "software--<SOFTWARE STIX OBJECT>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ]
}
```

To generate the id of SRO, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `relationship_type+source_collection_name/source_ref+target_collection_name/target_ref`  values.

All generated objects are stored in the source edge collection.

#### 7. Sigma Rule Indicator -> ATT&CK Attack Pattern relationship (`sigma-attack`)

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

#### 8. Sigma Rule Indicator -> CVE Vulnerability (`sigma-cve`)

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
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ]
}
```

To generate the id of SRO, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `relationship_type+source_collection_name/source_ref+target_collection_name/target_ref`  values.

All generated objects are stored in the source edge collection.

#### 9. CVE (`vulnerability`) -> ATT&CK (`attack-pattern`)

At the time of writing, this is my favourite relationship in CTI Butler. It makes it possible to search for CVEs using MITRE ATT&CK Techniques.

To do this, arango_cti_processor uses the latest OpenAI models to generate mappings.

Using `description` inside each Vulnerability object inside the `nvd_cpe_vertex_collection`, the following prompt is used;

```
[CVE DESCRIPTION]

What MITRE ATT&CK techniques and subtechniques are being described in this text?

For each ATT&CK technique or sub-technique identified, print your response as only JSON in the following structure:

{
    attack_id: "ID",
    attack_name: "NAME",
    confidence_score: "SCORE"
}

Where confidence score defines how sure you are this technique or subtechnique is being described in the text (between 0 [lowest] and 1 [highest])
```

This will return response that looks as follows;

```json
[
    {
        "attack_id": "T1078",
        "attack_name": "Valid Accounts",
        "confidence_score": "0.9"
    },
    {
        "attack_id": "T1110.001",
        "attack_name": "Password Guessing",
        "confidence_score": "0.6"
    }
]
```

Anything with a confidence greater than 0.4 (e.g. Active Scanning above) is considered that the CVE is referencing an ATT&CK technique in CTI Butler (this threshold can be manually set in your own install of stix2arango if you disagree).

The `attack_id` returned by the AI can be searched against the STIX `attack-pattern` object `external_references.external_id` property values (where `external_references.source_name=mitre-attack`) as follows

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

When a match is found, an SRO is created as follows;

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUID V5 LOGIC>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<indicator.created>",
    "modified": "<indicator.modified>",
    "relationship_type": "exploited-using",
    "source_ref": "vulnerability--<SIGMA INDICATOR STIX OBJECT>",
    "target_ref": "attack-pattern--<CVE VULNERABILITY STIX OBJECT>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ]
}
```

#### Updating SROs on subsequent runs

This script is designed to run on demand. On each run, it will create new relationships or update existing relationships based on changes to imported data (using stix2arango).

arango_cti_processor will always filter the results to `_is_latest==true` before applying any updates. This means older versions of objects will not be considered when generating relationships.

arango_cti_processor will also generate a `_record_md5_hash` property of the relationships created each time. If the `_record_md5_hash` for the `id` already exists in the DB at insert time, then the record will be skipped (as no update detected).

Each time an update is detected, arango_cti_processor will mark previously created SROs for the object as `_is_latest=false` and then recreate the SROs (but ensure the `_record_created` time matches old objects updated as is latest is false, but update the `_record_modified` time accordingly to match the update time).

Similarly, when a record is removed from a source object (e.g ATT&CK reference removed from a CAPEC object), the object removed between updates is marked at `_is_latest=false`, but no new object recreated for it (because it no longer exist in latest version of source object)

### Creating groupings

arango_cti_processor also creates non-relationship Grouping objects.

#### 1. CPE groupings (`cpe-groups`)

* Source collection: `nvd_cpe_vertex_collection` (`type==software` objects only)

There are millions of CPEs. As such there are often many CPEs for a single vendor / product (e.g. Microsoft has the product Word which has many versions).

A unique product can be identified as follows;

```sql
LET uniqueVendorProducts = (
  FOR doc IN nvd_cpe_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc.type == "software"
    LET cpe_parts = SPLIT(doc.cpe, ":")
    LET vendor = cpe_parts[3]
    LET product = cpe_parts[4]
    COLLECT vendorProduct = CONCAT(vendor, ":", product) WITH COUNT INTO length
    RETURN vendorProduct
)

RETURN LENGTH(uniqueVendorProducts)
```

To help users deal with this volume when search, for every unique product name in a CPE, ArangoDB CTI Processor creates a grouping object;

```json
{
    "type": "grouping",
    "spec_version": "2.1",
    "id": "grouping--<UUID V5 LOGIC>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<FIRST CREATED CPE FOR PRODUCT DATE>",
    "modified": "<LAST MODIFIED CPE FOR PRODUCT DATE>",
    "name": "Product: <PRODUCT NAME>",
    "context": "unspecified",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ],
    "object_refs": [
        "software--<ALL SOFTWARE SCOS IDS FOR PRODUCTS>",
        "software--<ALL SOFTWARE SCOS IDS FOR PRODUCTS>"
    ]
}
```

To generate the id of the object, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `PRODUCT NAME IN CPE URI`.

They are inserted into ArangoDB as follows;

```sql
LET groupings = [
    {
        "_key": "<THE OBJECTS STIX ID>",
        "_arango_cti_processor_note": "<RELATIONSHIP LINK>",
        "_record_created": "<DATETIME OBJECT WAS INSERTED IN DB>",
        "_record_modified": "<DATETIME OBJECT WAS LAST MODIFIED IN DB>",
        "_record_md5_hash": "<HASH OF OBJECT>",
        "_is_latest": true,
        "_is_ref": false,
        "<STIX Grouping OBJECT PROPERTIES>"
    }
]
FOR grouping IN groupings
INSERT grouping INTO nvd_cpe_vertex_collection
```

Product Grouping objects are then grouped by the vendor.

A unique vendor can be identified as follows;

```sql
LET uniqueVendors = (
  FOR doc IN nvd_cpe_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc.type == "software"
    LET cpe_parts = SPLIT(doc.cpe, ":")
    LET vendor = cpe_parts[3]
    COLLECT uniqueVendor = vendor WITH COUNT INTO length
    RETURN uniqueVendor
)

RETURN LENGTH(uniqueVendors)
```

For every unique vendor shown in software objects a grouping object is also created;

```json
{
    "type": "grouping",
    "spec_version": "2.1",
    "id": "grouping--<UUID V5 LOGIC>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<FIRST CREATED CPE FOR VENDOR DATE>",
    "modified": "<LAST MODIFIED CPE FOR VENDOR DATE>",
    "name": "Vendor: <VENDOR NAME>",
    "context": "unspecified",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ],
    "object_refs": [
        "grouping--<ALL GROUPING SDOS FOR VENDOR PRODUCTS>",
        "grouping--<ALL GROUPING SDOS FOR VENDOR PRODUCTS>"
    ]
}
```

To generate the id of the object, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `VENDOR NAME` as the value.

All objects are stored in the source vertex collection (`nvd_cpe_vertex_collection`).

#### Updating groupings on subsequent runs

Updates are handled in the same way they are for relationships.