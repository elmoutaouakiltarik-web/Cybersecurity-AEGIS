from __future__ import annotations


def level_from_score(score: float) -> str:
    if score >= 80: return 'critical'
    if score >= 55: return 'high'
    if score >= 25: return 'medium'
    return 'low'


def recommended_action(risk_level: str, family: str | None = None, ot_ics: bool = False) -> str:
    if ot_ics:
        if risk_level in {'critical','high'}:
            return 'OT/ICS: alert, preserve evidence, notify responsible engineer, require human approval before containment.'
        return 'OT/ICS: monitor read-only and correlate with asset baseline.'
    if risk_level == 'critical':
        return 'Investigate immediately; isolate host/network segment if confirmed by SOC policy.'
    if risk_level == 'high':
        return 'Prioritize investigation; enrich with SIEM, EDR and threat intelligence.'
    if risk_level == 'medium':
        return 'Review and correlate with asset/user context.'
    return 'Monitor.'
