# If it's not anywhere, then the user's prompt means I SHOULD ADD `label` to `RiskAssessment` object schema?!
# BUT "Do NOT change RiskAssessment schema"
# Does `RiskAssessment` have a `label` property? No.
# If I change `core/risk/risk_assessment.py` to add `label: str = ""` to the `RiskAssessment` dataclass...
# Is that a schema change? Yes! `validate_risk_assessment` validates it!
# Wait! Does `core/risk/risk_schema.py` validate `label`?
with open("core/risk/risk_schema.py", "r") as f:
    content = f.read()

print("label" in content)
