from arango_cti_processor.tools.utils import import_default_objects, get_embedded_refs


def test_import_default_objects(session_processor):
    import_default_objects(
        session_processor, [], collections=["mitre_capec_vertex_collection"]
    )
    query = """
    FOR d IN mitre_capec_vertex_collection
    FILTER d._arango_cti_processor_note == "automatically imported object at script runtime"
    RETURN d.id
    """
    stix_ids = session_processor.execute_raw_query(query)
    assert stix_ids == [
        "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
    ]


def test_get_embedded_refs():
    assert get_embedded_refs(
        {
            "abc_ref": "ref1",
            "abcd_refs": ["ref1", "ref2"],
            "abcde": [{"abcdef_ref": "ref7"}, {"abcd_efgh_ref": "ref8"}],
        }
    ) == [
        ("abc", "ref1"),
        ("abcd", "ref1"),
        ("abcd", "ref2"),
        ("abcde-abcdef", "ref7"),
        ("abcde-abcd-efgh", "ref8"),
    ]
