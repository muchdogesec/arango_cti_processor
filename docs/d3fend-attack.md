## D3fend Attack Pattern -> MITRE Attack Pattern relationship (`d3fend-knowledgebases`)

* Source collection: `def3nd_vertex_collection` (`type==weakness` objects only)
* Destination collections: `mitre_attack_enterprise_vertex_collection`, `mitre_attack_mobile_vertex_collection`, `mitre_attack_ics_vertex_collection` (`type==attack-pattern` objects only)

#### d3fend API 

The following API maps d3fend objects to ATT&CK techniques

https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json

Here is a sample of an object in the response:

```json
      {
        "query_def_tech_label": {
          "type": "literal",
          "value": "Credential Hardening"
        },
        "top_def_tech_label": {
          "type": "literal",
          "value": "Credential Hardening"
        },
        "def_tactic_label": {
          "type": "literal",
          "value": "Harden"
        },
        "def_tactic_rel_label": {
          "type": "literal",
          "value": "enables"
        },
        "def_tech_label": {
          "type": "literal",
          "value": "Credential Rotation"
        },
        "def_artifact_rel_label": {
          "type": "literal",
          "value": "regenerates"
        },
        "def_artifact_label": {
          "type": "literal",
          "value": "Credential"
        },
        "off_artifact_label": {
          "type": "literal",
          "value": "Access Token"
        },
        "off_artifact_rel_label": {
          "type": "literal",
          "value": "accesses"
        },
        "off_tech_label": {
          "type": "literal",
          "value": "Steal Application Access Token"
        },
        "off_tech_id": {
          "type": "literal",
          "value": "T1528"
        },
        "off_tech_parent_label": {
          "type": "literal",
          "value": "Credential Access Technique"
        },
        "off_tech_parent_is_toplevel": {
          "datatype": "http://www.w3.org/2001/XMLSchema#boolean",
          "type": "literal",
          "value": "true"
        },
        "off_tactic_rel_label": {
          "type": "literal",
          "value": "enables"
        },
        "off_tactic_label": {
          "type": "literal",
          "value": "Credential Access"
        },
        "def_tactic": {
          "type": "uri",
          "value": "http://d3fend.mitre.org/ontologies/d3fend.owl#Harden"
        },
        "def_tactic_rel": {
          "type": "uri",
          "value": "http://d3fend.mitre.org/ontologies/d3fend.owl#enables"
        },
        "def_tech": {
          "type": "uri",
          "value": "http://d3fend.mitre.org/ontologies/d3fend.owl#CredentialRotation"
        },
        "def_artifact_rel": {
          "type": "uri",
          "value": "http://d3fend.mitre.org/ontologies/d3fend.owl#regenerates"
        },
        "def_artifact": {
          "type": "uri",
          "value": "http://d3fend.mitre.org/ontologies/d3fend.owl#Credential"
        },
        "off_artifact": {
          "type": "uri",
          "value": "http://d3fend.mitre.org/ontologies/d3fend.owl#AccessToken"
        },
        "off_artifact_rel": {
          "type": "uri",
          "value": "http://d3fend.mitre.org/ontologies/d3fend.owl#accesses"
        },
        "off_tech": {
          "type": "uri",
          "value": "http://d3fend.mitre.org/ontologies/d3fend.owl#T1528"
        },
        "off_tech_parent": {
          "type": "uri",
          "value": "http://d3fend.mitre.org/ontologies/d3fend.owl#CredentialAccessTechnique"
        },
        "off_tactic_rel": {
          "type": "uri",
          "value": "http://d3fend.mitre.org/ontologies/d3fend.owl#enables"
        },
        "off_tactic": {
          "type": "uri",
          "value": "http://d3fend.mitre.org/ontologies/d3fend.owl#TA0006"
        }
      },
```

### Defensive-side fields (`def_*`)

#### Defensive tactic

- `def_tactic` URI of the D3FEND defensive tactic (e.g. `#Harden`)
- `def_tactic_label` Human-readable name of the tactic (e.g. `Harden`)

#### Defensive tactic → technique relationship

- `def_tactic_rel` Predicate connecting the tactic to the technique
- `def_tactic_rel_label` Label for that relationship (e.g. `enables`)

#### Defensive technique

- `def_tech` URI of the D3FEND defensive technique
- `def_tech_label` Name of the defensive technique (e.g. `Token Binding`)

#### Defensive technique → artifact relationship

- `def_artifact_rel` Predicate describing how the defensive technique acts on an artifact
- `def_artifact_rel_label` Label for that relationship (e.g. `strengthens`)

#### Defensive artifact

- `def_artifact` URI of the D3FEND digital artifact
- `def_artifact_label` Name of the artifact (e.g. `Access Token`)

---

### Offensive-side fields (`off_*`)

#### Offensive technique (ATT&CK)

- `off_tech` URI of the offensive technique node
- `off_tech_label` Name of the ATT&CK technique (e.g. `Steal Application Access Token`)
- `off_tech_id` ATT&CK technique ID (e.g. `T1528`)

#### Offensive technique parent (hierarchy)

- `off_tech_parent` URI of the parent category of the offensive technique
- `off_tech_parent_label` Name of the parent category (e.g. `Credential Access Technique`)
- `off_tech_parent_is_toplevel` Boolean indicating whether the parent is considered top-level

#### Offensive tactic

- `off_tactic` URI of the ATT&CK tactic
- `off_tactic_label` Name of the tactic (e.g. `Credential Access`)

#### Offensive tactic → technique relationship

- `off_tactic_rel` Predicate connecting the offensive tactic to the offensive technique
- `off_tactic_rel_label` Label for that relationship (commonly `enables`)

#### Offensive technique → artifact relationship

- `off_artifact_rel` Predicate describing how the offensive technique interacts with an artifact
- `off_artifact_rel_label`  Label for that relationship (e.g. `accesses`)

#### Offensive artifact

- `off_artifact` URI of the affected digital artifact
- `off_artifact_label` Name of the artifact (e.g. `Access Token`)

## Mapping

The API response contains both internal relationships (Tactic->Technique, Technique->Artifact) and external (Technique->ATT&CK). The internal relationships are covered in the core STIX bundle for d3fend, so only the external ones matter here.

### Fields used for linking

| Role | Field |
|----|----|
| D3FEND technique | `def_tech` |
| D3FEND technique name | `def_tech_label` |
| ATT&CK technique ID | `off_tech_id` |
| ATT&CK technique name | `off_tech_label` |
| Shared artifact | `def_artifact_label` = `off_artifact_label` |
| Defensive relationship | `def_artifact_rel_label` |
| Offensive relationship | `off_artifact_rel_label` |

### Example

- Defensive technique: `Token Binding`
- Defensive action: `strengthens` → `Access Token`
- Artifact: `Access Token`
- Offensive technique: `T1528 – Steal Application Access Token`
- Offensive action: `accesses` → `Access Token`

d3fend and ATT&CK are joined on the artifacts (e.g. Access Token))

```
def_tech_label ──def_artifact_rel──▶ def_artifact_label ◀──off_artifact_rel── off_tech_label (off_tech_id)
```

e.g.  Credential Rotation ──▶ regenerates ──▶ Credential ◀── accesses ◀──  Steal Application Access Token (T1528)


This part `def_tech_label ──def_artifact_rel──▶ def_artifact_label` is covered in the core knowledgebase.

So we need to join the Artifact to the ATT&CK object like so...

```json
{
  "type": "relationship",
  "id": "relationship--<UUID v5>",
  "created": "<target.created>",
  "modified": "<target.modified>",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "relationship_type": "<off_artifact_rel>",
  "source_ref": "attack-pattern--<ATTACK TECHNIQUE OBJECT>",
  "target_ref": "indicator--<D3FEND ARTIFACT>",
  "description": "<off_tech_label (off_tech_id)> <off_artifact_rel> <def_artifact_label>",
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