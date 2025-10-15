def remove_volatile_keys(objects, extra_keys=[]):
    for obj in objects:
        for k in ["_rev", "_record_created", "_record_modified", *extra_keys]:
            obj.pop(k, None)
    return objects