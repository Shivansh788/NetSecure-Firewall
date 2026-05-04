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
                r1.get("source_zone") == r2.get("source_zone")
                and r1.get("dest_zone") == r2.get("dest_zone")
                and r1.get("protocol") == r2.get("protocol")
                and r1.get("port") == r2.get("port")
            ):

                # Different actions = conflict
                if r1.get("action") != r2.get("action"):
                    conflicts.append((r1.get("id"), r2.get("id")))

    return conflicts