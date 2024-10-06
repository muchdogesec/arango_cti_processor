# Arango CTI Processor

![](docs/arango_cti_processor.png)

A small script that creates relationships between common CTI knowledge-bases in STIX 2.1 format.

## tl;dr

[![arango_cti_processor](https://img.youtube.com/vi/2GVVC2RfIq8/0.jpg)](https://www.youtube.com/watch?v=2GVVC2RfIq8)

[Watch the demo](https://www.youtube.com/watch?v=2GVVC2RfIq8).

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

Assumes the database entered at the command line has the following collection names;

* `mitre_attack_enterprise_vertex_collection`/`mitre_attack_enterprise_edge_collection`
* `mitre_attack_mobile_vertex_collection`/`mitre_attack_mobile_edge_collection`
* `mitre_attack_ics_vertex_collection`/`mitre_attack_ics_edge_collection`
* `mitre_capec_vertex_collection`/`mitre_capec_edge_collection`
* `mitre_cwe_vertex_collection`/`mitre_cwe_edge_collection`
* `nvd_cpe_vertex_collection`/`nvd_cpe_edge_collection`
* `nvd_cve_vertex_collection`/`nvd_cve_edge_collection`
* `sigma_rules_vertex_collection`/`sigma_rules_edge_collection`

[These utilities in stix2arango will do this automatically for you](https://github.com/muchdogesec/stix2arango/tree/main/utilities).

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
    --database DATABASE \
    --relationship RELATIONSHIP \
    --ignore_embedded_relationships BOOLEAN \
    --stix2arango_note STRING
```

Where;

* `--database` (required): the arangoDB database name where the objects you want to link are found. It must contain the collections required for the `--relationship` option(s) selected
* `--relationship` (optional, dictionary): you can apply updates to certain relationships at run time. Default is all. Note, you should ensure your `database` contains all the required seeded data. User can select from;
	* `capec-attack`
  * `capec-cwe`
  * `cwe-capec`
  * `attack-capec` (archived -- ATT&CK objects no longer contain references to CAPEC)
  * `cve-cwe`
  * `cve-cpe`
  * `cve-epss`
  * `sigma-attack`
  * `sigma-cve`
* `--ignore_embedded_relationships` (optional, boolean). Default is false. if `true` passed, this will stop any embedded relationships from being generated. This is a stix2arango feature where STIX SROs will also be created for `_ref` and `_refs` properties inside each object (e.g. if `_ref` property = `identity--1234` and SRO between the object with the `_ref` property and `identity--1234` will be created). See stix2arango docs for more detail if required, essentially this a wrapper for the same `--ignore_embedded_relationships` setting implemented by stix2arango
* `--stix2arango_note` (optional, string): will be used as a value for `_stix2arango_note` for all objects created by arango_cti_processor
* `--modified_min` (optional, date). By default arango_cti_processor will consider all objects in the database specified with the property `_is_latest==true` (that is; the latest version of the object). Using this flag with a modified time value will further filter the results processed by arango_cti_processor to STIX objects with a `modified` time >= to the value specified. This is most useful in CVE modes, where a high volume of CVEs are published daily.

On each run, only the `_is_latest==true` version of objects will be considered by the script.

### Examples

```shell
python3 arango_cti_processor.py \
  --database arango_cti_processor_standard_tests_database \
  --relationship capec-attack \
  --stix2arango_note test01 \
  --ignore_embedded_relationships false 
```

## Backfilling data

[stix2arango contains a set of utility scripts that can be used to backfill all the datasources required for this test](https://github.com/muchdogesec/stix2arango/tree/main/utilities).

## How it works

If you would like to know how the logic of this script works in detail, please consult the `/docs` directory.

## Useful supporting tools

* To generate STIX 2.1 extensions: [stix2 Python Lib](https://stix2.readthedocs.io/en/latest/)
* STIX 2.1 specifications for objects: [STIX 2.1 docs](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
* [ArangoDB docs](https://www.arangodb.com/docs/stable/)

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).