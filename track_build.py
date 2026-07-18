import re
with open("core/risk/risk_builder.py", "r") as f:
    content = f.read()

new_logic = """        score = min(sum(item.score for item in contributions), 100)
        risk_level = self._risk_level(score)
        label = f"[{risk_level.value}] {chain.title}"

        assessment = RiskAssessment(
            id=stable_risk_assessment_id(chain.id, self.policy_version),
            attack_chain_id=chain.id,
            score=score,
            risk_level=risk_level,
            contributions=contributions,
            summary=f"Risk score {score} for attack chain {chain.id}.",
            recommendation=self._recommendation(chain),
            created_at=(
                created_at or datetime.now(UTC).replace(microsecond=0).isoformat()
            ),
            policy_version=self.policy_version,
            label=label,
        )"""

content = re.sub(r'        score = min\(sum\(item\.score for item in contributions\), 100\)\n        assessment = RiskAssessment\([\s\S]*?            policy_version=self\.policy_version,\n        \)', new_logic, content)

with open("core/risk/risk_builder.py", "w") as f:
    f.write(content)
