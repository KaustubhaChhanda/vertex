from typing import Dict, Any, List

class XAIExplainer:
    """
    Standardizes human-readable Explainable AI (XAI) outputs,
    MITRE ATT&CK TTP associations, and evidence factor contributions.
    """

    @staticmethod
    def format_threat_explanation(
        threat_type: str,
        risk_score: float,
        risk_tier: str,
        factors: List[Dict[str, Any]],
        context_details: str = ""
    ) -> str:
        top_factors = sorted(factors, key=lambda x: abs(x.get("contribution", 0.0)), reverse=True)[:3]
        factor_summaries = [f"{f.get('factor')}: {f.get('value')}" for f in top_factors if f.get("value")]

        explanation = f"[{risk_tier} Risk | Score: {risk_score:.2f}] {threat_type} detected. "
        if factor_summaries:
            explanation += f"Key evidence: {'; '.join(factor_summaries)}. "
        if context_details:
            explanation += f"{context_details}."
            
        return explanation.strip()
