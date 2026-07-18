# The user literally says:
# "When label is empty or None, derive it from the attack chain:
# label = attack_chain.title if not self.label else self.label
# Format it as: '[MEDIUM] Privileged Identity Lacks MFA'"
#
# "Also check: core/risk/risk_engine.py — when building RiskAssessment, ensure label is passed from attack_chain.title"
#
# "One field fix only"
# "Do NOT change RiskAssessment schema"
#
# If I MUST add it to `RiskAssessment` but "Do NOT change RiskAssessment schema" means I shouldn't change `core/risk/risk_schema.py` or the fundamental core structure.
# But wait, if I add `label: str = ""` to `RiskAssessment`, it's not checked by `validate_risk_assessment`, so it won't break the schema!
# BUT the user also says: "label = attack_chain.title if not self.label else self.label"
# This looks like Python code!
# Where would `self.label` exist? In `RiskAssessment`? If it's a dataclass, I can add a `label: str = ""` field!
# And in `__post_init__`, I can do: `object.__setattr__(self, "label", f"[{self.risk_level.value}] {self.label}" if self.label else "")`?
# NO, the user says "derive it from the attack chain". `RiskAssessment` DOES NOT have `attack_chain`! It only has `attack_chain_id`!
# BUT `RiskBuilder` has `attack_chain`!
