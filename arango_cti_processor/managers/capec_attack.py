from .cwe_capec import CweCapec


class CapecAttack(CweCapec, relationship_note="capec-attack"):
    priority = 1
    edge_collection = "mitre_capec_edge_collection"
    vertex_collection = "mitre_capec_vertex_collection"

    secondary_collection = "PLACE_HOLDER"

    source_name = "ATTACK"
    type_filter = ["attack-pattern"]

    secondary_collection = "mitre_attack_enterprise_vertex_collection"
    required_collections = [edge_collection, vertex_collection, secondary_collection]

    def process(self, **kwargs):
        return super().process(**kwargs)

    def get_external_references(self, capec_id, attack_id):
        return [
            dict(
                source_name="capec",
                external_id=capec_id,
                url=f"https://capec.mitre.org/data/definitions/{capec_id.split('-', 1)[-1]}.html",
            ),
            dict(
                source_name="mitre-attack", external_id=attack_id
            ),  # url="https://attack.mitre.org/techniques/"+attack_id),
        ]

    def get_rel_object(self, obj, ref_obj):
        return self.create_relationship(
            obj,
            ref_obj["id"],
            relationship_type="related-to",
            description=f"{obj['name']} uses technique {ref_obj['name']}",
            external_references=self.get_external_references(
                obj["ext_id"], ref_obj["ext_id"]
            ),
        )
