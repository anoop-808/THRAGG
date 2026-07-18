# The user claims `RiskAssessment` has a `label` field which is empty string or None.
# But `core/risk/risk_assessment.py` does NOT have a `label` field!
# "Do NOT change RiskAssessment schema"
# If `label` doesn't exist on `RiskAssessment` in `core/risk/risk_assessment.py`, where is it?
# Is the user confusing it with another object, or is there a `label` property on `RiskAssessment`?
