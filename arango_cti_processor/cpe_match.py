
from __future__ import annotations
import logging
import math
import os
import time
from urllib.parse import parse_qsl, urlparse
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
def fetch_cpe_matches(cve_id, criteria_ids):
    url = config.CPEMATCH_API_ENDPOINT + f"?cveId={cve_id}"
    total_results = math.inf
    start_index = 0
    backoff_time = 10
    uri = urlparse(url)
    query = dict(parse_qsl(uri.query))
    cpe_names_all = {}

    while start_index < total_results:
        module_logger.info(f"Calling NVD API `{uri.path}` with startIndex: {start_index}", )
        query.update({
            "startIndex": start_index,
            "resultsPerPage":500,
        })

        try:
            module_logger.info(f"Query => {query}")
            response = requests.get(url, query, headers=dict(apiKey=os.getenv("NVD_API_KEY")))
            module_logger.info(f"Status Code => {response.status_code}")
            if response.status_code != 200:
                module_logger.warning("Got response status code %d.", response.status_code)
                raise requests.ConnectionError

        except requests.ConnectionError as ex:
            module_logger.warning(
                "Got ConnectionError. Backing off for %d seconds.", backoff_time
            )
            time.sleep(backoff_time)
            backoff_time *= 1.5
            continue

        

        content = response.json()
        start_index += content["resultsPerPage"]
        total_results = content["totalResults"]
        if start_index < total_results:
            time.sleep(5)
        cpe_names_all.update(parse_into(content, criteria_ids))
    return cpe_names_all



def parse_into(response: dict, criteria_ids: dict[str, bool]):
    cpe_names = {}
    for match_data in response.get("matchStrings", []):
        match_data = match_data["matchString"]
        criteria_id = match_data["matchCriteriaId"]
        if criteria_id not in criteria_ids:
            continue
        is_vulnerable = criteria_ids[criteria_id]
        for cpe in match_data.get("matches", []):
            cpe_names[cpe["cpeName"]] = is_vulnerable
    return cpe_names