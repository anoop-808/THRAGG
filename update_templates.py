import json

with open("core/attack_chain/attack_templates.json", "r") as f:
    data = json.load(f)

new_template = {
  "id": "ATTACK-CHAIN-IDENTITY-COMPROMISE",
  "name": "Identity Compromise via MFA Gap",
  "description": "Attacker exploits accounts lacking MFA to gain unauthorized access to identity infrastructure.",
  "mitre_chain": ["T1078"],
  "required_entities": ["IDENTITY"],
  "required_findings": [],
  "entry_point_type": "IDENTITY",
  "confidence_base": 0.75,
  "severity": "HIGH",
  "tags": ["identity", "mfa-gap"]
}

data["templates"].append(new_template)

with open("core/attack_chain/attack_templates.json", "w") as f:
    json.dump(data, f, indent=2)
