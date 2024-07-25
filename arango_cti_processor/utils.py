from __future__ import annotations
import logging
import uuid
import json
import hashlib
import requests
import re
from . import config
from tqdm import tqdm

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .cti_processor import ArangoProcessor as CTIProcessor

from stix2 import Relationship, Grouping
from datetime import datetime

module_logger = logging.getLogger("data_ingestion_service")

def get_relationship():
    return {
        "mitre_capec_vertex_collection": {
            "capec-attack": relate_capec_to_attack,
            "capec-cwe": relate_capec_to_cwe,
        },
        "mitre_cwe_vertex_collection": {"cwe-capec": relate_cwe_to_capec},
        "mitre_attack_enterprise_vertex_collection": {
            "attack-capec": relate_attack_to_capec
        },
        "mitre_attack_ics_vertex_collection": {"attack-capec": relate_attack_to_capec},
        "mitre_attack_mobile_vertex_collection": {
            "attack-capec": relate_attack_to_capec
        },
        "nvd_cve_vertex_collection": {
            "cve-cwe": relate_cve_to_cwe,
            "cve-cpe": relate_cve_to_cpe,
            "cve-attack": relate_cve_to_attack,
        },
        "sigmahq_rules_vertex_collection": {
            "sigma-attack": relate_sigma_to_attack,
            "sigma-cve": relate_sigma_to_cve,
        },
    }

def load_file_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        return response.text
    except requests.exceptions.RequestException as e:
        module_logger.error(f"Error loading JSON from {url}: {e}")
        return None


def read_file_data(filename: str):
    with open(filename, "r") as input_file:
        file_data = input_file.read()
        try:
            data = json.loads(file_data)
        except Exception as e:
            raise Exception("Invalid file type")
    return data


def get_rel_func_mapping():
    return {
        "capec-attack": {"mitre_capec_vertex_collection": relate_capec_to_attack},
        "capec-cwe": {"mitre_capec_vertex_collection": relate_capec_to_cwe},
        "cwe-capec": {"mitre_cwe_vertex_collection": relate_cwe_to_capec},
        "attack-capec": {
            "mitre_attack_enterprise_vertex_collection": relate_attack_to_capec,
            "mitre_attack_ics_vertex_collection": relate_attack_to_capec,
            "mitre_attack_mobile_vertex_collection": relate_attack_to_capec,
        },
        "cve-cwe": {"nvd_cve_vertex_collection": relate_cve_to_cwe},
        "cve-cpe": {"nvd_cve_vertex_collection": relate_cve_to_cpe},
        "sigma-attack": {"sigmahq_rules_vertex_collection": relate_sigma_to_attack},
        "sigma-cve": {"sigmahq_rules_vertex_collection": relate_sigma_to_cve},
        "cve-attack": {"nvd_cve_vertex_collection": relate_cve_to_attack},
    }


def validate_collections(collections):
    required_collections = config.COLLECTION_EDGE + config.COLLECTION_VERTEX
    if len(list(set(required_collections) - set(collections))) > 0:
        missing_collections = "\n ".join(
            list(set(required_collections) - set(collections))
        )
        print(
            f"The following collections are missing. Please add them to continue. \n {missing_collections}"
        )
        return True


def verify_duplication(obj, object_list):
    if isinstance(object_list, list) and isinstance(obj, dict):
        match_string = f'"_key": "{obj.get("_key")}",'
        filtered_list = [obj_ for obj_ in object_list if match_string in obj_]
        if len(filtered_list) > 0:
            return True
    return False


def parse_relation_object(data, result, collection, relationship_type: str, note=None):
    generated_id = "relationship--" + str(
        uuid.uuid5(
            config.namespace,
            "{}+{}/{}+{}".format(
                relationship_type, collection, data.get("id"), result.get("_id")
            ),
        )
    )
    obj = json.loads(
        Relationship(
            id=generated_id,
            created=data.get("created"),
            modified=data.get("modified"),
            relationship_type=relationship_type,
            source_ref=data.get("id"),
            target_ref=result.get("id"),
            created_by_ref="identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            object_marking_refs=config.OBJECT_MARKING_REFS,
            external_references=[
                # ExternalReference(source_name="cti2stix_version", external_id=config.cti2stix_version),
            ],
        ).serialize()
    )
    obj["_from"] = data["_id"]
    obj["_to"]   = result["_id"]
    obj["_is_ref"] = False
    obj["_arango_cti_processor_note"] = note
    obj["_record_md5_hash"] = generate_md5(obj)
    return obj


def relate_capec_to_cwe(data, db: CTIProcessor, collection, collect_edge, notes):
    objects = []
    try:
        capec_id = ""
        if data.get("external_references", None):
            for rel in data.get("external_references", None):
                if rel.get("source_name") == "capec":
                    capec_id = rel.get("external_id")

                if rel.get("source_name") == "cwe":
                    custom_query = (
                        "FILTER "
                        "POSITION(doc.external_references[*].external_id, '{}', false)"
                        " ".format(rel.get("external_id"))
                    )
                    results = db.filter_objects_in_collection_using_custom_query(
                        "mitre_cwe_vertex_collection", custom_query
                    )
                    for result in results:

                        rel = parse_relation_object(
                            data, result, collection, relationship_type="exploits", note="capec-cwe"
                        )
                        objects.append(rel)
    except Exception as e:
        module_logger.exception(e)
    return objects


def relate_cve_to_cpe(data, db: CTIProcessor, collection, collect_edge, notes):
    try:
        objects = []
        if data.get("type") == "indicator":
            pattern = r"software:cpe='(.*?)'"
            matches = re.findall(pattern, data.get("pattern"))
            custom_query = f"FILTER doc.cpe IN {matches}"
            results = db.filter_objects_in_collection_using_custom_query(
                collection_name="nvd_cpe_vertex_collection", custom_query=custom_query
            )

            for result in results:
                rel = parse_relation_object(
                    data, result, collection, relationship_type="pattern-contains", note="cve-cpe"
                )
                objects.append(rel)
    except Exception as e:
        module_logger.exception(e)
    return objects


def relate_cve_to_cwe(data, db: CTIProcessor, collection, collect_edge, notes):
    logging.info("relate_cve_to_cwe")
    objects = []
    try:
        if data.get("external_references", None):
            for rel in data.get("external_references", None):
                if rel.get("source_name") == "cve":
                    cve_id = rel.get("external_id")

                if rel.get("source_name") == "cwe":
                    custom_query = (
                        "FILTER "
                        "POSITION(doc.external_references[*].external_id, '{}', false)"
                        " ".format(rel.get("external_id"))
                    )
                    results = db.filter_objects_in_collection_using_custom_query(
                        "mitre_cwe_vertex_collection", custom_query
                    )
                    for result in results:
                        rel = parse_relation_object(
                            data,
                            result,
                            collection,
                            relationship_type="exploited-using",
                            note="cve-cwe"
                        )
                        objects.append(rel)
    except Exception as e:
        module_logger.exception(e)
    return objects


def set_latest_for(db: CTIProcessor, id, collection):
    query = """
    LET records = (
        FOR doc in @@collection
        FILTER doc.id == @id
        LET _time = doc.modified ? doc.modified : doc._record_modified
        return {_time, _key: doc._key, _is_latest: doc._is_latest}
    )
    LET _time = MAX(records[*]._time)

    FOR record in records
    LET _is_latest = _time == record._time
    UPDATE record WITH {_is_latest} IN @@collection
    RETURN [_is_latest, record._is_latest]

    """
    return db.arango.execute_raw_query(
        query,
        bind_vars={
            "@collection": collection,
            "id": id,
        },
    )


def relate_capec_to_attack(
    data, db: CTIProcessor, collection, collection_edge, notes: str
):
    objects = []
    try:
        capec_id = ""
        # updated(4) -> final(0) False --> updated(4) True
        if data.get("type") == "attack-pattern" and data.get(
            "external_references", None
        ):
            
            for rel in data.get("external_references", None):
                if rel.get("source_name") == "capec":
                    capec_id = rel.get("external_id")
                if rel.get("source_name") == "ATTACK":
                    custom_query = (
                        "FILTER "
                        "POSITION(t.external_references[*].external_id, '{}', false) and t._is_latest==True"
                        " ".format(rel.get("external_id"))
                    )
                    collections_ = []
                    for vertex in config.COLLECTION_VERTEX:
                        if "attack" in vertex:
                            collections_.append(vertex)
                    results = db.filter_objects_in_list_collection_using_custom_query(
                        collection_list=collections_, filters=custom_query
                    )[0]
                    for result in results:
                        rel = parse_relation_object(
                            data, result, collection, relationship_type="technique", note="capec-attack"
                        )
                        objects.append(rel)
    except Exception as e:
        module_logger.exception(e)
    return objects


def relate_cwe_to_capec(data, db: CTIProcessor, collection, collection_edge, notes):
    logging.info("relate_cwe_to_capec")
    objects = []
    try:
        cwe_id = ""
        if data.get("external_references", None):
            
            for rel in data.get("external_references", None):
                if rel.get("source_name") == "cwe":
                    cwe_id = rel.get("external_id")
                if rel.get("source_name") == "capec":
                    custom_query = (
                        "FILTER "
                        "POSITION(doc.external_references[*].external_id, '{}', false)"
                        " ".format(rel.get("external_id"))
                    )
                    results = db.filter_objects_in_collection_using_custom_query(
                        "mitre_capec_vertex_collection", custom_query
                    )

                    for result in results:
                        rel = parse_relation_object(
                            data,
                            result,
                            collection,
                            relationship_type="exploited-using",
                            note="cwe-capec"
                        )
                        objects.append(rel)

    except Exception as e:
        module_logger.exception(e)
    return objects


def relate_attack_to_capec(
    data, db: CTIProcessor, collection_vertex: str, collection_edge: str, notes: str
):
    logging.info("relate_attack_to_capec")
    objects = []
    try:
        attack_id = ""
        if data.get("external_references", None):
            for rel in data.get("external_references", None):
                
                if rel.get("source_name") == "mitre-attack":
                    attack_id = rel.get("external_id")

                if rel.get("source_name") == "capec":
                    module_logger.info(rel)
                    custom_query = (
                        "FILTER "
                        "POSITION(doc.external_references[*].external_id, '{}', false) and doc._is_latest==True "
                        " ".format(rel.get("external_id"))
                    )
                    results = db.filter_objects_in_collection_using_custom_query(
                        collection_name="mitre_capec_vertex_collection",
                        custom_query=custom_query,
                    )
                    for result in results:
                        rel = parse_relation_object(
                            data,
                            result,
                            collection_vertex,
                            relationship_type="relies-on",
                            note="attack-capec"
                        )
                        objects.append(rel)
    except Exception as e:
        module_logger.exception(e)
    return objects


def relate_sigma_to_attack(
    data, db: CTIProcessor, collection_vertex: str, collection_edge: str, notes: str
):
    logging.info("relate_sigma_to_attack")
    if data.get("type") != "indicator" or data.get("pattern_type") != "sigma":
        return []
    objects = []
    try:
        for ref in data.get("external_references", []):
            if ref["source_name"] == "mitre-attack":
                custom_query = (
                    "FILTER "
                    "t.type == 'attack-pattern' AND POSITION(t.external_references[*].external_id, '{}', false) AND t._is_latest==True"
                    " ".format(ref["external_id"])
                )
            elif ref["source_name"] == "ATTACK":
                custom_query = (
                    "FILTER t.name=='{}' "
                    "AND t._is_latest==True "
                    "AND t.type == 'x-mitre-tactic'".format(
                        ref["description"]
                        .replace("_", " ")
                        .title()
                        .replace(" And ", " and ")
                    )
                )
            else:
                continue

            collections_ = []
            for vertex in config.COLLECTION_VERTEX:
                if "attack" in vertex:
                    collections_.append(vertex)
            results = db.filter_objects_in_list_collection_using_custom_query(
                collection_list=collections_, filters=custom_query
            )[0]

            for result in results:
                rel = parse_relation_object(
                    data, result, collection_vertex, relationship_type="detects", note="sigma-attack"
                )
                objects.append(rel)
    except Exception as e:
        module_logger.exception(e)
    return objects


def relate_sigma_to_cve(
    data, db: CTIProcessor, collection_vertex: str, collection_edge: str, notes: str
):
    objects = []
    logging.info("relate_sigma_to_cve")
    if data.get("type") != "indicator" or data.get("pattern_type") != "sigma":
        return objects
    try:
        for ref in data.get("external_references", []):
            if ref["source_name"].lower() == "cve":
                custom_query = (
                    "FILTER "
                    "doc.name=='{}' and doc._is_latest==True and doc.type=='vulnerability'"
                    " ".format(ref["external_id"].upper())
                )
                results = db.filter_objects_in_collection_using_custom_query(
                    collection_name="nvd_cve_vertex_collection",
                    custom_query=custom_query,
                )
                for result in results:
                    rel = parse_relation_object(
                        data, result, collection_vertex, relationship_type="detects", note="sigma-cve"
                    )
                    objects.append(rel)
    except Exception as e:
        module_logger.exception(e)
    return objects


def verify_threshold(response):
    res_array = []
    for res in response:
        if res[1] > config.SMET_THRESHOLD:
            res_array.append(res[0])
    return res_array


def relate_cve_to_attack(
    data, db: CTIProcessor, collection_vertex: str, collection_edge: str, notes: str
):
    if not config.SMET_ACTIVATE or data.get("type") != "vulnerability":
        return []
    objects = []
    try:

        response = map_text(data.get("description"))

        custom_query = f"FILTER t.name IN {verify_threshold(response)}"
        collections_ = []
        for vertex in config.COLLECTION_VERTEX:
            if "attack" in vertex:
                collections_.append(vertex)
        results = db.filter_objects_in_list_collection_using_custom_query(
            collection_list=collections_, filters=custom_query
        )
        for result in results[0]:
            rel = parse_relation_object(
                data, result, collection_vertex, relationship_type="targets", note="cve-attack"
            )
            objects.append(rel)
            
    except Exception as e:
        module_logger.exception(e)
    return objects


def generate_md5(obj: dict):
    obj_copy = {k: v for k, v in obj.items() if not k.startswith("_")}
    obj_copy["_arango_cti_processor_note"] = obj.get("_arango_cti_processor_note")
    json_str = json.dumps(obj_copy, sort_keys=True, default=str).encode("utf-8")
    return hashlib.md5(json_str).hexdigest()


def prepare_vendor_group_object(db: CTIProcessor, vendor_list: object) -> list:
    objects = []
    def create_new_vendor_object(
        db: CTIProcessor, vendor, product, collect_name, created=None
    ):
        query = (
            "LET software_ids = (FOR doc IN nvd_cpe_vertex_collection "
            "FILTER doc._arango_cti_processor_note != 'automatically imported object at script runtime' "
            f"AND doc.type == 'software' AND doc.vendor == '{vendor}' RETURN doc._key) "
            "FOR doc IN nvd_cpe_vertex_collection FILTER doc._arango_cti_processor_note != 'automatically imported object at script runtime' "
            "AND doc.type == 'grouping' AND LENGTH(INTERSECTION(doc.object_refs, software_ids)) > 0 RETURN doc.id"
        )
        results = db.arango.execute_raw_query(query=query)
        if len(results) > 0:
            group = {
                "id": "grouping--{}".format(
                    str(uuid.uuid5(config.namespace, f"{vendor}"))
                ),
                "created_by_ref": "identity--8afa110b-fdbc-4a4e-ab47-211bb822bc6c",
                "created": datetime.now() if created else datetime.now(),
                "modified": datetime.now(),
                "name": f"Vendor: {vendor}",
                "context": "unspecified",
                "object_marking_refs": config.OBJECT_MARKING_REFS,
                "object_refs": list(set(results)),
            }
            grouping_ = json.loads(Grouping(**group).serialize())
            grouping_["_arango_cti_processor_note"] = "cpe-groups"
            grouping_["_record_md5_hash"] = generate_md5(group)
            query = (
                f"FOR doc IN nvd_cpe_vertex_collection "
                f"FILTER doc.id =='{grouping_.get('id')}' "
                f"AND doc.type == 'grouping' AND doc.object_refs == {results} "
                f"RETURN doc.id"
            )
            result = db.arango.execute_raw_query(query=query)
            if len(result) > 0:
                return
            objects.append(grouping_)
        return

    for vendor in tqdm(vendor_list):
        try:
            vendor_ = vendor[0]
            if vendor_ == "\\":
                vendor_ = re.escape(vendor[0])
            vendor_ = vendor_.replace("\\", "\\\\")
            product_ = vendor[1]
            if product_ == "\\":
                product_ = re.escape(product_)
            product_ = product_.replace("\\", "\\\\")
            product_ = re.escape(vendor[1])
            if vendor:
                query = (
                    f"FOR doc IN nvd_cpe_vertex_collection "
                    f"FILTER doc.type=='grouping' "
                    f"AND doc.name like 'Vendor: {vendor_}' RETURN doc"
                )
                results = db.arango.execute_raw_query(query=query)
                if len(results) == 0:
                    create_new_vendor_object(
                        db, vendor_, product_, collect_name="nvd_cpe_vertex_collection"
                    )
                else:
                    create_new_vendor_object(
                        db,
                        vendor_,
                        product_,
                        collect_name="nvd_cpe_vertex_collection",
                        created=results[0].get("created"),
                    )

        except Exception as e:
            module_logger.exception(e)
    db.upsert_several_objects_chunked(objects, "nvd_cpe_vertex_collection")
    return objects


def prepare_products_grouping_object(db: CTIProcessor, product_list: list) -> list:
    objects = []
    def create_new_product_group(
        db: CTIProcessor, product, org_product, collect_name, created=None
    ):
        query = (
            f"FOR doc IN nvd_cpe_vertex_collection "
            f"FILTER doc.cpe like '%:{product}:%' AND doc.type == 'software' "
            "RETURN doc.id"
        )
        result = db.arango.execute_raw_query(query=query)
        if len(result) > 0:
            group = {
                "id": "grouping--{}".format(
                    str(uuid.uuid5(config.namespace, f"{product}"))
                ),
                "created_by_ref": "identity--8afa110b-fdbc-4a4e-ab47-211bb822bc6c",
                "created": datetime.now() if created else created,
                "modified": datetime.now(),
                "name": f"Product: {org_product}",
                "context": "unspecified",
                "object_marking_refs": config.OBJECT_MARKING_REFS,
                "object_refs": list(set(result)),
            }
            grouping_ = json.loads(Grouping(**group).serialize())
            grouping_["_arango_cti_processor_note"] = "cpe-groups"
            grouping_["_record_md5_hash"] = generate_md5(group)
            query = (
                f"FOR doc IN nvd_cpe_vertex_collection "
                f"FILTER doc.id =='{grouping_.get('id')}' "
                f"AND doc.type == 'grouping' AND doc.object_refs == {result} "
                f"RETURN doc.id"
            )
            result = db.arango.execute_raw_query(query=query)
            if len(result) > 0:
                return
            objects.append(grouping_)
        return 

    for product in tqdm(product_list):

        if product:
            org_product = product
            if "\\" in product and "\\" != product:
                product = product.replace("\\", "%")
            if "\\" == product:
                product = product.replace("\\", "\\\\")
            query = (
                f"FOR doc in nvd_cpe_vertex_collection "
                f"FILTER doc.name like '%: {product}' AND doc.type=='grouping' return doc"
            )
            result = db.arango.execute_raw_query(query=query)
            if not len(result) > 0:
                create_new_product_group(
                    db, product, org_product, collect_name="nvd_cpe_vertex_collection"
                )
            else:
                create_new_product_group(
                    db,
                    product,
                    org_product,
                    collect_name="nvd_cpe_vertex_collection",
                    created=result[0].get("created"),
                )
    db.upsert_several_objects_chunked(objects, "nvd_cpe_vertex_collection")
    return objects


def cpe_groups(db: CTIProcessor):
    logging.info("Working on CPE - Grouping Task")
    logging.info("Working on CPE - Grouping Products")
    custom_query = (
        "FOR doc IN nvd_cpe_vertex_collection "
        "FILTER doc._stix2arango_note !='automatically imported on collection creation' "
        "AND doc.type == 'software'"
        "LET cpe_parts = SPLIT(doc.cpe, ':') LET product = cpe_parts[4] RETURN product"
    )
    product_list = list(set(db.arango.execute_raw_query(custom_query)))
    inserted_data_products = prepare_products_grouping_object(db, product_list)
    logging.info("Working on CPE - Grouping Vendors")

    custom_query = (
        "FOR doc IN nvd_cpe_vertex_collection "
        "FILTER doc._stix2arango_note != 'automatically imported on collection creation' "
        "AND doc.type == 'software' LET cpe_parts = SPLIT(doc.cpe, ':') "
        "LET vendor = cpe_parts[3] LET products = cpe_parts[4] RETURN [vendor,products]"
    )
    vendor_list = db.arango.execute_raw_query(custom_query)
    inserted_data_vendor = prepare_vendor_group_object(db, vendor_list)
    return inserted_data_products + inserted_data_vendor


def sigma_groups(db: CTIProcessor):
    return []
