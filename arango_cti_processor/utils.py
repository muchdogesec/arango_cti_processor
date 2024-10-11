from __future__ import annotations
import logging
import math
import time
from urllib.parse import parse_qsl, urlparse
import uuid
import json
import hashlib
import requests
import re
from stix2 import Note
from stix2.serialization import serialize

from arango_cti_processor.epss import EPSSManager

from .cpe_match import fetch_cpe_matches
from . import config
from tqdm import tqdm

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .cti_processor import ArangoProcessor as CTIProcessor

from stix2 import Relationship, Grouping
from datetime import datetime

module_logger = logging.getLogger("data_ingestion_service")

def stix_to_dict(obj):
    return json.loads(serialize(obj))
    

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


def get_rel_func_mapping(relationships):
    REL_TO_FUNC_MAPPING = {
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
        "sigma-attack": {"sigma_rules_vertex_collection": relate_sigma_to_attack},
        "sigma-cve": {"sigma_rules_vertex_collection": relate_sigma_to_cve},
        "cve-attack": {"nvd_cve_vertex_collection": relate_cve_to_attack},
        "cve-epss": {"nvd_cve_vertex_collection": generate_epss},
    }
    return [
        (rel, value)
        for rel, value in REL_TO_FUNC_MAPPING.items()
        if rel in relationships
    ]


def parse_relation_object(src, dst, collection, relationship_type: str, note=None, is_embedded_ref=False, description=None):
    generated_id = "relationship--" + str(
        uuid.uuid5(
            config.namespace,
            f"{relationship_type}+{src.get('_id').split('+')[0]}+{dst.get('_id').split('+')[0]}",
        )
    )
    obj = dict(
        id=generated_id,
        type="relationship",
        created=src.get("created"),
        modified=src.get("modified"),
        relationship_type=relationship_type,
        source_ref=src.get("id"),
        target_ref=dst.get("id"),
        created_by_ref=config.IDENTITY_REF,
        object_marking_refs=config.OBJECT_MARKING_REFS,
    )
    if description:
        obj['description'] = description
    obj["_from"] = src["_id"]
    obj["_to"] = dst["_id"]
    obj["_is_ref"] = is_embedded_ref
    if note:
        obj["_arango_cti_processor_note"] = note
    obj["_record_md5_hash"] = generate_md5(obj)
    return obj


def relate_capec_to_cwe(data, db: CTIProcessor, collection, collect_edge, notes, **kwargs):
    objects = []
    try:
        capec_name = get_external_ref_by_name(data, 'capec')
        for rel in data.get("external_references", []):
            if rel.get("source_name") == "cwe":
                cwe_name = rel.get("external_id")
                custom_query = (
                    "FILTER "
                    "POSITION(doc.external_references[*].external_id, '{}', false)"
                    " ".format(cwe_name)
                )
                results = db.filter_objects_in_collection_using_custom_query(
                    "mitre_cwe_vertex_collection", custom_query
                )
                for result in results:

                    rel = parse_relation_object(
                        data,
                        result,
                        collection,
                        relationship_type="exploits",
                        note=notes,
                        description=f"{capec_name} exploits {cwe_name}",
                    )
                    objects.append(rel)
    except Exception as e:
        module_logger.exception(e)
    return objects


def match_cve_ids(matchers, cve_name):
    if not matchers:
        return True
    for r in matchers:
        if re.match(r, cve_name, re.IGNORECASE):
            return True
    return False

def retrieve_epss_metrics(epss_url, cve_id):
    url = f"{epss_url}?cve={cve_id}"
    response = requests.get(url)
    #logger.info(f"Status Code => {response.status_code}")
    if response.status_code != 200:
        module_logger.warning("Got response status code %d.", response.status_code)
        raise requests.ConnectionError

    data = response.json()
    extensions = {}
    if epss_data := data.get('data'):
        for key, source_name in [('epss', 'score'), ('percentile', 'percentile'), ('date', 'date')]:
            extensions[source_name] = epss_data[0].get(key)
    return extensions

def generate_epss(vulnerability, db: CTIProcessor, collection, collection_edge, notes: str, cve_ids=None, **kwargs):
    objects = []
    try:
        cve_name = vulnerability.get('name')
        if vulnerability["type"] != "vulnerability" or not match_cve_ids(cve_ids, cve_name):
            return []
        
        cve_id = vulnerability['name']
        epss_data = EPSSManager.get_data_for_cve(cve_id)
        content = f"EPSS Score for {cve_id}"
        stix_id = vulnerability['id'].replace("vulnerability", "note")

        if epss_data:
            epss_data = [epss_data]
        else:
            epss_data = []
        
        if not epss_data:
            return []
        
        modified = datetime.strptime(epss_data[-1]["date"], "%Y-%m-%d").date()

        query = f"""
        FOR doc IN @@collection
        FILTER doc.id == @stix_id
        REMOVE doc IN @@collection
        RETURN doc
        """
        

        db_note = list(db.arango.db.aql.execute(query, bind_vars={'@collection': 'nvd_cve_vertex_collection', "stix_id": stix_id}))
        note: dict = db_note and db_note[0]

        if not note:
            return [stix_to_dict(Note(
                    id=stix_id,
                    created=vulnerability['created'],
                    modified=modified,
                    content=content,
                    x_epss=epss_data,
                    object_refs=[
                        vulnerability['id'],
                    ],
                    extensions= {
                        "extension-definition--efd26d23-d37d-5cf2-ac95-a101e46ce11d": {
                            "extension_type": "toplevel-property-extension"
                        }
                    },
                    object_marking_refs=list(set(vulnerability['object_marking_refs']+config.OBJECT_MARKING_REFS)),
                    created_by_ref=config.IDENTITY_REF,
                    external_references=vulnerability['external_references'][:1],
                ))]
        else:
            existing_dates = set(map(lambda x: x['date'], note['x_epss']))
            if existing_dates.issuperset([epss_data[0]['date']]):
                return [note]
            note.update(
                x_epss=sorted(epss_data+note['x_epss'], key=lambda epss: epss['date'], reverse=True),
            )
            note.update(
                modified=datetime.strptime(note['x_epss'][0]["date"], "%Y-%m-%d")
            )
            return [stix_to_dict(note)]
    except Exception as e:
        pass
    return objects

def relate_cve_to_cpe(data, db: CTIProcessor, collection, collect_edge, notes, **kwargs):
    try:
        objects = []
        if data.get("type") == "indicator":
            criteria_ids = {}
            x_cpes = data.get('x_cpes', {})

            for vv in x_cpes.get('vulnerable', []):
                criteria_ids[vv['matchCriteriaId']] = True
            for vv in x_cpes.get('not_vulnerable', []):
                criteria_ids[vv['matchCriteriaId']] = False
            cpe_names = fetch_cpe_matches(data['name'], criteria_ids)
            bind_vars = {
                'cpe_names': list(cpe_names)
            }
            custom_query = f"FILTER doc.cpe IN @cpe_names"
            results = db.filter_objects_in_collection_using_custom_query(
                collection_name="nvd_cpe_vertex_collection", custom_query=custom_query, bind_vars=bind_vars
            )

            for result in results:
                rel = parse_relation_object(
                    data,
                    result,
                    collection,
                    relationship_type="pattern-contains",
                    note=notes,
                    description=f"{data['name']} pattern contains {result['name']}",
                )
                objects.append(rel)
                if cpe_names[result["cpe"]]:
                    rel2 = parse_relation_object(
                        data,
                        result,
                        collection,
                        relationship_type="is-vulnerable",
                        note=notes,
                        description=f"{data['name']} is vulnerable {result['name']}",
                    )
                    objects.append(rel2)

    except Exception as e:
        module_logger.exception(e)
    return objects


def relate_cve_to_cwe(data, db: CTIProcessor, collection, collect_edge, notes, **kwargs):
    logging.info("relate_cve_to_cwe")
    objects = []
    try:
        cve_name = get_external_ref_by_name(data, 'cve')
        for rel in data.get("external_references", []):
            if rel.get("source_name") == "cwe":
                cwe_name = rel.get("external_id")
                custom_query = (
                    "FILTER "
                    "POSITION(doc.external_references[*].external_id, '{}', false)"
                    " ".format(cwe_name)
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
                        note=notes,
                        description=f"{cve_name} is exploited using {cwe_name}",
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

def get_external_ref_by_name(data, source_name) -> dict:
    for ref in data.get("external_references", []):
        if ref.get('source_name') == source_name:
            return ref.get('external_id')
    return None

def relate_capec_to_attack(
    data, db: CTIProcessor, collection, collection_edge, notes: str, **kwargs
):
    objects = []
    try:
        # updated(4) -> final(0) False --> updated(4) True
        
        capec_name = get_external_ref_by_name(data, 'capec')
        if not capec_name or data.get("type") != "attack-pattern" or not data.get("external_references"):
            return []
        for rel in data["external_references"]:
            if rel.get("source_name") in ["ATTACK"]:
                attack_name = rel.get("external_id")
                custom_query = (
                    "FILTER "
                    "POSITION(t.external_references[*].external_id, '{}', false) and t._is_latest"
                    " ".format(attack_name)
                )
                collections_ = [
                    vertex for vertex in db.vertex_collections if "attack" in vertex
                ]
                results = db.filter_objects_in_list_collection_using_custom_query(
                    collection_list=collections_, filters=custom_query
                )[0]
                for result in results:
                    rel = parse_relation_object(
                        data,
                        result,
                        collection,
                        relationship_type="technique",
                        note=notes,
                        description=f"{capec_name} uses technique {attack_name}",
                    )
                    objects.append(rel)
    except Exception as e:
        module_logger.exception(e)
    return objects


def relate_cwe_to_capec(data, db: CTIProcessor, collection, collection_edge, notes, **kwargs):
    logging.info("relate_cwe_to_capec")
    objects = []
    try:
        cwe_id = get_external_ref_by_name(data, 'cwe')
        for rel in data.get("external_references", []):
            if rel.get("source_name") == "capec":
                capec_id = rel.get("external_id")
                custom_query = (
                    "FILTER "
                    "POSITION(doc.external_references[*].external_id, '{}', false)"
                    " ".format(capec_id)
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
                        note=notes,
                        description=f"{cwe_id} is exploited using {capec_id}",
                    )
                    objects.append(rel)

    except Exception as e:
        module_logger.exception(e)
    return objects


def relate_attack_to_capec(
    data, db: CTIProcessor, collection_vertex: str, collection_edge: str, notes: str, **kwargs
):
    logging.info("relate_attack_to_capec")
    objects = []
    try:
        attack_name = get_external_ref_by_name(data, 'mitre-attack')
        if not attack_name:
            return objects
        for rel in data.get("external_references", []):
            if rel.get("source_name") == "capec":
                module_logger.info(rel)
                capec_name = rel.get("external_id")
                custom_query = (
                    "FILTER "
                    "POSITION(doc.external_references[*].external_id, '{}', false) and doc._is_latest "
                    " ".format(capec_name)
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
                        note=notes,
                        description=f"{attack_name} relies on {capec_name}",
                    )
                    objects.append(rel)
    except Exception as e:
        module_logger.exception(e)
    return objects


def relate_sigma_to_attack(
    data, db: CTIProcessor, collection_vertex: str, collection_edge: str, notes: str, **kwargs
):
    logging.info("relate_sigma_to_attack")
    if data.get("type") != "indicator" or data.get("pattern_type") != "sigma":
        return []
    objects = []
    try:
        sigma_name = data.get('name')
        for ref in data.get("external_references", []):
            if ref["source_name"] != "mitre-attack":
                continue
            external_id: str = ref.get('external_id', '')
            if external_id.startswith('T'):
                #technique
                custom_query = (
                    "FILTER "
                    "t.type == 'attack-pattern' AND POSITION(t.external_references[*].external_id, '{}', false) AND t._is_latest"
                    " ".format(ref["external_id"])
                )
            elif external_id.startswith('S'):
                #software
                custom_query = (
                    "FILTER "
                    "t.type == 'tool' AND POSITION(t.external_references[*].external_id, '{}', false) AND t._is_latest"
                    " ".format(ref["external_id"])
                )
            elif external_id.startswith('G'):
                #grouping
                custom_query = (
                    "FILTER "
                    "t.type == 'intrusion-set' AND POSITION(t.external_references[*].external_id, '{}', false) AND t._is_latest"
                    " ".format(ref["external_id"])
                )
            else:
                #tactic
                custom_query = (
                    "FILTER t.type == 'x-mitre-tactic' "
                    "AND t._is_latest "
                    "AND t.x_mitre_shortname=='{}'".format(external_id.replace("_", "-"))
                )

            collections_ = []
            for vertex in db.vertex_collections:
                if "attack" in vertex:
                    collections_.append(vertex)
            results = db.filter_objects_in_list_collection_using_custom_query(
                collection_list=collections_, filters=custom_query
            )[0]

            for result in results:
                rel = parse_relation_object(
                    data,
                    result,
                    collection_vertex,
                    relationship_type="detects",
                    note=notes,
                    description=f"{sigma_name} detects {external_id}",
                )
                objects.append(rel)
    except Exception as e:
        module_logger.exception(e)
    return objects


def relate_sigma_to_cve(
    data, db: CTIProcessor, collection_vertex: str, collection_edge: str, notes: str, **kwargs
):
    objects = []
    logging.info("relate_sigma_to_cve")
    if data.get("type") != "indicator" or data.get("pattern_type") != "sigma":
        return objects
    try:
        sigma_name = data.get('name')
        for ref in data.get("external_references", []):
            if ref["source_name"].lower() == "cve":
                cve_name = ref["external_id"].upper()
                custom_query = (
                    "FILTER "
                    "doc.name=='{}' and doc._is_latest and doc.type=='vulnerability'"
                    " ".format(cve_name)
                )
                results = db.filter_objects_in_collection_using_custom_query(
                    collection_name="nvd_cve_vertex_collection",
                    custom_query=custom_query,
                )
                for result in results:
                    rel = parse_relation_object(
                        data,
                        result,
                        collection_vertex,
                        relationship_type="detects",
                        note=notes,
                        description=f"{sigma_name} detects {cve_name}",
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
    data, db: CTIProcessor, collection_vertex: str, collection_edge: str, notes: str, **kwargs
):
    if not config.SMET_ACTIVATE or data.get("type") != "vulnerability":
        return []
    objects = []
    try:

        response = map_text(data.get("description"))

        custom_query = f"FILTER t.name IN {verify_threshold(response)}"
        collections_ = []
        for vertex in db.vertex_collections:
            if "attack" in vertex:
                collections_.append(vertex)
        results = db.filter_objects_in_list_collection_using_custom_query(
            collection_list=collections_, filters=custom_query
        )
        for result in results[0]:
            rel = parse_relation_object(
                data,
                result,
                collection_vertex,
                relationship_type="targets",
                note=notes
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


def sigma_groups(db: CTIProcessor):
    return []

EMBEDDED_RELATIONSHIP_RE = re.compile(r"([a-z_]+)_refs{0,1}")

def get_embedded_refs(object: list|dict, xpath: list = []):
    embedded_refs = []
    if isinstance(object, dict):
        for key, value in object.items():
            if key in ["source_ref", "target_ref"]:
                continue
            if match := EMBEDDED_RELATIONSHIP_RE.fullmatch(key):
                relationship_type = "-".join(xpath + match.group(1).split('_'))
                targets = value if isinstance(value, list) else [value]
                for target in targets:
                    embedded_refs.append((relationship_type, target))
            elif isinstance(value, list):
                embedded_refs.extend(get_embedded_refs(value, xpath + [key]))
    elif isinstance(object, list):
        for obj in object:
            if isinstance(obj, dict):
                embedded_refs.extend(get_embedded_refs(obj, xpath))
    return embedded_refs
