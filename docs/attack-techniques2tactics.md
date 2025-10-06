## Attack Technique -> Tactics

**IMPORTANT**: this mode is run automatically when it detects `kill_chain_phases`

IN ATT&CK/DISARM/ATLAS Techniques and Sub-techniques are linked to Tactics using the `kill_chain_phases` in the Attack Pattern objects.

e.g. for Access Token Manipulation (T1134)

```json
  "kill_chain_phases": [
    {
      "kill_chain_name": "mitre-attack",
      "phase_name": "defense-evasion"
    },
    {
      "kill_chain_name": "mitre-attack",
      "phase_name": "privilege-escalation"
    }
  ],
```

is linked to the Tactics defense-evasion (TA0005) and privilege-escalation TA0004

Graphing these relationships without this translation layer is difficult.

Therefore CTI Butler creates an SRO between the `attack-pattern` (tech/sub tech) and the `x-mitre-tactic` (tactic) object as follows;

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUIDV5 GENERATION LOGIC>",
    "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    "created": "<TECHNIQUE CREATED TIME>",
    "modified": "<TECHNIQUE MODIFIED TIME>",
    "relationship_type": "related-to",
    "source_ref": "attack-pattern--<ATT&CK TECH STIX OBJECT ID>",
    "target_ref": "x-mitre-tactic--<ATT&CK TACTIC STIX OBJECT ID>",
    "description": "Technique <ID> (<NAME>) belongs to Tactic <ID> (<NAME>",
    "external_references": [
    	{
		    "source_name": "mitre-attack",
		    "url": "https://attack.mitre.org/techniques/<ID>/<ID>",
		    "external_id": "<ID>"
        },
	    {
	       	"source_name": "mitre-attack",
	         "url": "https://attack.mitre.org/tactics/<ID>",
	         "external_id": "<ID>"
	    }
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "arking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
}
```

**Note**: above shows sub-technique. Techniques `external_references` values won't have two IDs in `url` path (will have just one).

To generate the id of SRO, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `relationship_type+source_ref+target_ref`

**IMPORTANT**: as shown above, it is possible that one tech/sub-tech can be linked to more than one Tactic.