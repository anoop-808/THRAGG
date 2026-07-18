# The user's output from the "CURRENT STATE":
# {
#   "id": "risk-f7e29e3ac6d38c5e",
#   "attack_chain_id": "chain-924b3fb8ae4f9d7c",
#   "score": 62,
#   "risk_level": "MEDIUM",
#   "label": ""   ← EMPTY
# }
# How did the user get this output? Maybe they added it themselves and want me to fix it, OR `label` is added dynamically in `to_dict`!
# Let's check `core/risk/risk_assessment.py` `to_dict` method!
with open("core/risk/risk_assessment.py", "r") as f:
    content = f.read()

print(content[content.find("def to_dict"):])
