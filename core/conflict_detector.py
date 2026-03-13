def detect_conflicts(rules):

    conflicts = []

    for i in range(len(rules)):
        for j in range(i + 1, len(rules)):

            r1 = rules[i]
            r2 = rules[j]

            # Skip disabled rules
            if not r1.get("enabled", True) or not r2.get("enabled", True):
                continue

            # Same matching conditions
            if (
                r1["source_zone"] == r2["source_zone"]
                and r1["dest_zone"] == r2["dest_zone"]
                and r1["protocol"] == r2["protocol"]
                and r1["port"] == r2["port"]
            ):

                # Different actions = conflict
                if r1["action"] != r2["action"]:
                    conflicts.append((r1["id"], r2["id"]))

    return conflicts