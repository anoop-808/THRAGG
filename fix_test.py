import re

with open("tests/test_risk_scoring.py", "r") as f:
    content = f.read()

new_fields = """        assert tuple(assessment.__dataclass_fields__) == (
            "id",
            "attack_chain_id",
            "score",
            "risk_level",
            "contributions",
            "summary",
            "recommendation",
            "created_at",
            "policy_version",
            "label",
            "priority_rank",
        )"""

content = re.sub(r'        assert tuple\(assessment\.__dataclass_fields__\) == \([\s\S]*?            "priority_rank",\n        \)', new_fields, content)
with open("tests/test_risk_scoring.py", "w") as f:
    f.write(content)
