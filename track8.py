# The prompt explicitly states: "Do NOT change RiskAssessment schema"
# If I don't change `RiskAssessment` dataclass, but the prompt says:
# "When label is empty or None, derive it from the attack chain: label = attack_chain.title if not self.label else self.label"
# "Format it as: '[MEDIUM] Privileged Identity Lacks MFA'"
# "Also check: core/risk/risk_engine.py — when building RiskAssessment, ensure label is passed from attack_chain.title"
# BUT THERE IS NO LABEL FIELD AT ALL!
# Let me look for ANY instance of `label` in `core/risk/risk_assessment.py`!
