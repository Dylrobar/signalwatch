"""Evidence tiers dominate CVE popularity; scores are not probabilities."""
import json
from datetime import datetime, timezone


def assess_priority(conn, alert, company_id='', owned=False):
    assessment = alert.get('assessment') or {}
    if isinstance(assessment, str):
        assessment = json.loads(assessment)
    exposure = assessment.get('exposure', {})
    verification = conn.execute('SELECT * FROM exposure_verifications WHERE subject_id=? AND company_id=?',
                                (alert['id'], company_id)).fetchone() if company_id and owned else None
    confirmed = bool(verification and verification['version'] == alert['version']
                     and verification['source_url'] == alert['source_url']
                     and verification['alert_first_seen'] == alert['first_seen']
                     and verification['expires_at'] > datetime.now(timezone.utc).isoformat()
                     and not assessment.get('evidence', {}).get('contradicting')
                     and assessment.get('applicability', {}).get('state') != 'false')
    supported = alert['version_state'] in ('exact', 'affected_range')
    confirmed &= supported
    # Nonoverlapping tiers prevent a popular unverified CVE outranking a verified exposure.
    tier = 'confirmed_exposure' if confirmed else 'owned_version_candidate' if owned and supported else 'version_candidate' if supported else 'inventory_context'
    base, ceiling = {'confirmed_exposure': (85, 100), 'owned_version_candidate': (50, 79),
                     'version_candidate': (20, 49), 'inventory_context': (0, 19)}[tier]
    severity = max(0, min(10, float(alert.get('severity') or 0)))
    epss = max(0, min(1, float(alert.get('epss') or 0)))
    score = round(min(ceiling, base + severity + (8 if alert.get('kev') else 0) + epss * 6), 2)
    why = ('Analyst verified an affected deployment and reachable vulnerable path on a confirmed owned asset.' if confirmed else
           'Published affected-version rules match observed inventory; runtime exposure still needs verification.')
    if alert.get('kev'):
        why += ' CISA reports exploitation of this CVE in the wild; that does not prove exploitation of this asset.'
    prerequisites = [p['requirement'] for p in exposure.get('prerequisites', []) if p.get('state') != 'true']
    fixed_version = None
    remediation_source = alert.get('url')
    if alert['advisory_id'] == 'CVE-2025-14180':
        from .exposure import PHP_PDO_ADVISORY
        remediation_source = PHP_PDO_ADVISORY
        branch = '.'.join(str(alert['version']).split('.')[:2])
        fixed_version = {'8.1': '8.1.34', '8.2': '8.2.30', '8.3': '8.3.29', '8.4': '8.4.16', '8.5': '8.5.1'}.get(branch)
    steps = [] if confirmed else ['Verify the installed package revision and distribution backport status on ' + alert['asset_id'] + '.',
                                 *prerequisites, 'Verify the affected component is enabled and reachable through the deployed application.']
    if fixed_version:
        steps.append('For upstream PHP, upgrade this branch to at least ' + fixed_version + '; for distribution packages, use the vendor security update that explicitly fixes CVE-2025-14180.')
    if confirmed:
        steps.append(verification['remediation'])
    steps += ['Apply the vendor-supported fixed release or mitigation from the linked advisory, then re-inventory this asset and verify the vulnerable path is removed.']
    return {'score': score, 'status': tier, 'tier': tier,
            'drivers': {'cvss': alert.get('severity'), 'kev': bool(alert.get('kev')), 'epss': alert.get('epss'),
                        'version_state': alert['version_state'], 'version_uncertain': not supported,
                        'ownership_confirmed': owned, 'runtime_verified': confirmed,
                        'recent_distinct_reporting': None, 'reporting_weight': 0},
            'why_this_matters': why,
            'remediation': {'asset_id': alert['asset_id'], 'product': alert.get('product'), 'observed_version': alert['version'],
                            'source_url': remediation_source, 'verification_evidence_url': verification['evidence_url'] if confirmed else None, 'steps': steps,
                            'fixed_version': fixed_version, 'fixed_version_status': 'Publisher-confirmed upstream PHP branch fix; distribution packages require their own advisory.' if fixed_version else 'Consult publisher; no universal fixed version inferred from affected bounds.'},
            'method': 'evidence-tiers-v2; confirmed 85–100, owned candidate 50–79, unverified ownership 20–49; reporting has zero weight'}
