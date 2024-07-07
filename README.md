# ArangoDB CTI Processor

A small script that creates relationships between common CTI knowledge-bases in STIX 2.1 format.

## Before you get started

If you do not want to backfill, maintain, or support your own CVE STIX objects check out CTI Butler which provides a fully manage database of these objects and more!

https://www.ctibutler.com/

## Overview

Here at DOGESEC we have many repositories that generate STIX objects for different knowledge-bases. Many of these knowledgebases often have some link to another.

For example, MITRE ATT&CK objects have references to MITRE CAPEC objects.

ArangoDB CTI Processor is a script that;

1. reads the ingested CTI from the supported sources in ArangoDB
2. creates STIX Relationships and Grouping objects to represent the relationships between them

ArangoDB CTI Processor is designed to work with the following data sources:

* MITRE ATT&CK
    * Enterprise
    * ICS
    * Mobile
* MITRE CWE
* MITRE CAPEC
* Sigma Rules
* NVD CPE
* NVD CVE

## Prerequisites

Assumes a database called `cti_database` with the following collections in it created by stix2arango;

* `mitre_attack_enterprise_vertex_collection`/`mitre_attack_enterprise_edge_collection`
* `mitre_attack_mobile_vertex_collection`/`mitre_attack_mobile_edge_collection`
* `mitre_attack_ics_vertex_collection`/`mitre_attack_ics_edge_collection`
* `mitre_capec_vertex_collection`/`mitre_capec_edge_collection`
* `mitre_cwe_vertex_collection`/`mitre_cwe_edge_collection`
* `nvd_cpe_vertex_collection`/`nvd_cpe_edge_collection`
* `nvd_cve_vertex_collection`/`nvd_cve_edge_collection`
* `sigma_rules_vertex_collection`/`sigma_rules_edge_collection`

[See the stix2arango README.md for more details on this](https://github.com/muchdogesec/stix2arango/).

## Usage

### Install the script

```shell
# clone the latest code
git clone https://github.com/muchdogesec/arango_cti_processor
# create a venv
cd arango_cti_processor
python3 -m venv arango_cti_processor-venv
source arango_cti_processor-venv/bin/activate
# install requirements
pip3 install -r requirements.txt
````

Note, the installation assumes ArangoDB is already installed locally.

[You can install ArangoDB here](https://arangodb.com/download/). arango_cti_processor is compatible with both the Enterprise and Community versions.

### Setup configoration options

You will need to create an `.env` file as follows;

```shell
cp .env.example .env
```

You will then need to specify details of your ArangoDB install (host, user, and password). It is important the user chosen has the ability to write/update new databases, collections and records.

### Run

```shell
python3 arango_cti_processor.py \
    --relationship ignore_embedded_relationships \
    --ignore_embedded_relationships BOOLEAN
```

Where;

* `--relationship` (optional, dictionary): you can apply updates to certain relationships at run time. Default is all . User can select from;
	* `capec-attack`
    * `capec-cwe`
    * `cwe-capec`
    * `attack-capec`
    * `cve-cwe`
    * `cve-cpe`
    * `sigma-attack`
    * `sigma-cve`
    * `cve-attack`
* `--ignore_embedded_relationships` (optional, boolean). Default is false. if `true` passed, this will stop any embedded relationships from being generated. This is a stix2arango feature where STIX SROs will also be created for `_ref` and `_refs` properties inside each object (e.g. if `_ref` property = `identity--1234` and SRO between the object with the `_ref` property and `identity--1234` will be created). See stix2arango docs for more detail if required.

On each run, only the `_is_latest==true` version of objects will be considered.

## Backfilling data

This repository includes a `scripts` directory that will backfill all the data you need to run arango_cti_processor.

There are two scripts one to download the latest data, the other to insert it using stix2arango

### 1. download data from remote sources

From this root of this code run this script;

```shell
sh scripts/download_data.sh
```

Note, this script will only download the latest version of the knowledgebases.

### 2. insert downloaded data

Install stix2arango, modify the script to replace `PATH_TO_ARANGO_CTI_PROCESSOR`, and run it from the stix2arango root directory;

```shell
sh scripts/insert_data.sh
```

## How it works

If you would like to know how the logic of this script works in detail, please consult the `/docs` directory.

## Useful supporting tools

* To generate STIX 2.1 extensions: [stix2 Python Lib](https://stix2.readthedocs.io/en/latest/)
* STIX 2.1 specifications for objects: [STIX 2.1 docs](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
* [ArangoDB docs](https://www.arangodb.com/docs/stable/)

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[AGPLv3](/LICENSE).