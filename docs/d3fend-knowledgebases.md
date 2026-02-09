## D3fend Attack Pattern -> MITRE Attack Pattern relationship (`d3fend-knowledgebases`)

* Source collection: `def3nd_vertex_collection` (`type==weakness` objects only)
* Destination collections: `mitre_attack_enterprise_vertex_collection`, `mitre_attack_mobile_vertex_collection`, `mitre_attack_ics_vertex_collection` (`type==attack-pattern` objects only)

### d3fend2stix output

d3fend2stix creates a relationship file that Arango CTI Processor uses to generate relationships.

This file is versioned and hosted on Cloudflare:

```
https://downloads.ctibutler.com/d3fend2stix-manual-output/d3fend-v{}-external-relationships.json
```

Mitigations

```json
    {
        "source": "d3f:M1056",
        "target": "d3f:DecoyEnvironment",
        "type": "d3f:related",
        "description": "Pre-compromise related Decoy Environment: Pre-compromise has a symmetric associative relation to Decoy Environment."
    },
```

Techniques/Subtechniques

```json
    {
        "source": "d3f:T1098.001",
        "target": "d3f:Credential",
        "type": "d3f:creates",
        "description": "Additional Cloud Credentials creates Credential: The subject Additional Cloud Credentials bring into existence an object Credential.  Some technique or agent Additional Cloud Credentials creates a persistent digital artifact Credential (as opposed to production of a consumable or transient object.); i.e., bring forth or generate"
    },
```

Weaknesses

```json
    {
        "source": "d3f:CWE-825",
        "target": "d3f:UserInputFunction",
        "type": "d3f:weakness-of",
        "description": ""
    },
```

## ATT&CK Mappings

Techniques/Subtechniques

```json
{
  "type": "relationship",
  "id": "relationship--<UUID v5>",
  "created": "<target.created>",
  "modified": "<target.modified>",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "relationship_type": "<off_artifact_rel>",
  "source_ref": "attack-pattern--<ATTACK OBJECT>",
  "target_ref": "indicator--<D3FEND ARTIFACT>",
  "description": "<ATT&CK ID> <ATT&CK NAME> <relationship_type> <D3FEND ID> <D3FEND NAME>",
  "external_references": [
    {
      "source_name": "mitre-attack",
      "url": "https://attack.mitre.org/techniques/<ID>",
      "external_id": "<ID>"
    },
    {
      "source_name": "mitre-d3fend",
      "url": "https://d3fend.mitre.org/dao/artifact/<ID>",
      "external_id": "<ID>",
            },
  ],
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
}
```

To generate the id of SRO, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `relationship_type+source_collection_name/source_ref+target_collection_name/target_ref` values.

Mitigations

```json
{
  "type": "relationship",
  "id": "relationship--<UUID v5>",
  "created": "<target.created>",
  "modified": "<target.modified>",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "relationship_type": "<off_artifact_rel>",
  "source_ref": "course-of-action--<ATTACK OBJECT>",
  "target_ref": "indicator--<D3FEND ARTIFACT>",
  "description": "<ATT&CK ID> <ATT&CK NAME> <relationship_type> <D3FEND ID> <D3FEND NAME>",
  "external_references": [
    {
      "source_name": "mitre-attack",
      "url": "https://attack.mitre.org/mitigations/<ID>",
      "external_id": "<ID>"
    },
    {
      "source_name": "mitre-d3fend",
      "url": "https://d3fend.mitre.org/dao/artifact/<ID>",
      "external_id": "<ID>",
            },
  ],
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
}
```

## CWE Mappings

```json
{
  "type": "relationship",
  "id": "relationship--<UUID v5>",
  "created": "<target.created>",
  "modified": "<target.modified>",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "relationship_type": "weakness-of",
  "source_ref": "weakness--<WEAKNESS OBJECT>",
  "target_ref": "indicator--<D3FEND ARTIFACT>",
  "description": "<WEAKNESS ID> <WEAKNESS NAME> <relationship_type> <D3FEND ID> <D3FEND NAME>",
  "external_references": [
    {
      "source_name": "cwe",
      "url": "http://cwe.mitre.org/data/definitions/<ID>",
      "external_id": "<ID>"
    },
    {
      "source_name": "mitre-d3fend",
      "url": "https://d3fend.mitre.org/dao/artifact/<ID>",
      "external_id": "<ID>",
            },
  ],
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
  ]
}
```