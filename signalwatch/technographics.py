import re

from .matching import normalize


METHOD = "technographic-context-v1"
TEXT_LIMIT = 64000
FINDING_LIMIT = 128
SNIPPET_LIMIT = 600

_TAXONOMY = (
    ("crowdstrike_falcon", "crowdstrike", "CrowdStrike", "falcon", "CrowdStrike Falcon", "EDR", "a", r"CrowdStrike\s+Falcon|Falcon\s+(?:sensor|platform)"),
    ("crowdstrike", "crowdstrike", "CrowdStrike", "crowdstrike", "CrowdStrike", "Security", "a", r"CrowdStrike"),
    ("panos", "paloaltonetworks", "Palo Alto Networks", "pan-os", "PAN-OS", "Firewall", "o", r"PAN[ -]?OS"),
    ("panorama", "paloaltonetworks", "Palo Alto Networks", "panorama", "Palo Alto Panorama", "Firewall Management", "a", r"Palo\s+Alto(?:\s+Networks)?\s+Panorama|Panorama(?=\s+(?:firewall|appliance|management|deployment)\b)"),
    ("globalprotect", "paloaltonetworks", "Palo Alto Networks", "globalprotect", "GlobalProtect", "VPN", "a", r"GlobalProtect"),
    ("paloalto", "paloaltonetworks", "Palo Alto Networks", "palo alto networks", "Palo Alto Networks", "Security", "a", r"Palo\s+Alto\s+Networks"),
    ("okta", "okta", "Okta", "okta", "Okta", "Identity", "a", r"Okta(?:\s+Verify)?"),
    ("snowflake", "snowflake", "Snowflake", "snowflake", "Snowflake", "Data Warehouse", "a", r"Snowflake"),
    ("eks", "amazon", "Amazon", "elastic_kubernetes_service", "AWS EKS", "Container Orchestration", "a", r"(?:AWS|Amazon)\s+EKS|(?:Amazon\s+)?Elastic\s+Kubernetes\s+Service"),
    ("splunk_enterprise", "splunk", "Splunk", "splunk", "Splunk Enterprise", "SIEM", "a", r"Splunk\s+Enterprise(?:\s+Security)?"),
    ("splunk_cloud", "splunk", "Splunk", "splunk_cloud", "Splunk Cloud", "SIEM", "a", r"Splunk\s+Cloud(?:\s+Platform)?"),
    ("splunk", "splunk", "Splunk", "splunk platform", "Splunk", "Observability", "a", r"Splunk"),
    ("fortios", "fortinet", "Fortinet", "fortios", "FortiOS", "Firewall", "o", r"FortiOS"),
    ("fortigate", "fortinet", "Fortinet", "fortigate", "FortiGate", "Firewall", "h", r"FortiGate"),
    ("fortinet", "fortinet", "Fortinet", "fortinet", "Fortinet", "Security", "a", r"Fortinet"),
    ("terraform", "hashicorp", "HashiCorp", "terraform", "Terraform", "IaC", "a", r"Terraform"),
    ("terragrunt", "gruntwork", "Gruntwork", "terragrunt", "Terragrunt", "IaC", "a", r"Terragrunt"),
    ("kubernetes", "kubernetes", "Kubernetes", "kubernetes", "Kubernetes", "Container Orchestration", "a", r"Kubernetes|K8s"),
    ("kafka", "apache", "Apache", "kafka", "Apache Kafka", "Messaging", "a", r"Apache\s+Kafka|Kafka"),
    ("gitlab", "gitlab", "GitLab", "gitlab", "GitLab", "CI/CD", "a", r"GitLab"),
    ("datadog", "datadog", "Datadog", "datadog", "Datadog", "Observability", "a", r"Datadog"),
    ("entra", "microsoft", "Microsoft", "entra_id", "Microsoft Entra ID", "Identity", "a", r"(?:Microsoft\s+)?Entra\s+ID|Azure\s+Active\s+Directory|Azure\s+AD"),
    ("intune", "microsoft", "Microsoft", "intune", "Microsoft Intune", "Device Management", "a", r"(?:Microsoft\s+)?Intune"),
    ("jamf_pro", "jamf", "Jamf", "jamf_pro", "Jamf Pro", "Device Management", "a", r"Jamf\s+Pro"),
    ("jamf", "jamf", "Jamf", "jamf", "Jamf", "Device Management", "a", r"Jamf"),
    ("windows_server", "microsoft", "Microsoft", "windows_server", "Windows Server", "Operating System", "o", r"(?:Microsoft\s+)?Windows\s+Server"),
    ("windows", "microsoft", "Microsoft", "windows", "Windows", "Operating System", "o", r"(?:Microsoft\s+)?Windows"),
    ("macos", "apple", "Apple", "macos", "macOS", "Operating System", "o", r"macOS|Mac\s+OS\s+X"),
    ("postgres", "postgresql", "PostgreSQL", "postgresql", "PostgreSQL", "Database", "a", r"PostgreSQL|Postgres"),
    ("oracle", "oracle", "Oracle", "database_server", "Oracle Database", "Database", "a", r"Oracle\s+(?:Database|DB|databases)"),
    ("aws", "amazon", "Amazon", "aws", "AWS", "Cloud", "a", r"Amazon\s+Web\s+Services|AWS"),
    ("azure", "microsoft", "Microsoft", "azure", "Azure", "Cloud", "a", r"(?:Microsoft\s+)?Azure"),
)
_PRODUCTS = {row[0]: row[1:7] for row in _TAXONOMY}
_TECH = re.compile(r"(?<![\w])(?:" + "|".join("(?P<" + row[0] + ">" + row[7] + ")" for row in _TAXONOMY) + r")(?![\w])", re.I)
_BOUNDARY = re.compile(r"(?<=[.!?])\s+|[\n;]+|\b(?:but|however|whereas)\b", re.I)
_VERSION = re.compile(r"\s*(?:(?:version|release|v)\s*)?(\d+(?:\.\d+){0,4}(?:(?:a|b|rc)\d+|[-+][\w.-]+)?)(?!\w|\.\d)", re.I)
_NEGATION = re.compile(r"\b(?:no\s+(?!longer\b)|without\s+|never\s+(?:(?:use|used|deploy|deployed|run|ran|adopt|adopted)\s+)?|(?:do(?:es)?\s+not|did\s+not|don['’]t|doesn['’]t|didn['’]t|not)\s+(?!only\b)(?:(?:currently|actively|actually|yet|use|used|using|deploy|deployed|run|running|adopt|adopted|operate)\s+){0,4})", re.I)
_REQUIREMENT = re.compile(r"\b(?:experience\s+(?:(?:working|hands[ -]on)\s+)?(?:with|in|of)|(?:familiarity|familiar|knowledge|proficiency|proficient|expertise|skills|background)\s+(?:with|in|of)|(?:requirements?|qualifications?)\s*:|(?:experience|required|preferred|familiarity)\s*:?\s*$)", re.I)
_ACTIVE = re.compile(r"\b(?:we\s+(?:(?:currently|actively|already|also|still)\s+)*(?:use|run|operate|maintain|manage|deploy|rely\s+on|monitor\s+with|are\s+(?:using|running|operating|maintaining|managing))|our\s+(?:[\w-]+\s+){0,3}(?:team|teams|engineers|organization|company)\s+(?:uses?|runs?|operates?|maintains?|manages?|deploys?))\b", re.I)
_HISTORICAL = re.compile(r"\b(?:previously|formerly|used\s+to|no\s+longer|retired|decommissioned|discontinued|phased\s+out)\b", re.I)
_PLANNED = re.compile(r"\b(?:plan(?:ning|s|ned)?\s+to|intend(?:ing|s)?\s+to|evaluat(?:e|es|ed|ing)|consider(?:ed|ing|s)?|propos(?:e|ed|ing)|will\s+(?:deploy|adopt|build|implement|introduce|use|migrate)|planned|upcoming|future)\b", re.I)
_MIGRATION = re.compile(r"\b(migrat(?:e|es|ed|ing)|mov(?:e|es|ed|ing)|replac(?:e|es|ed|ing))\b", re.I)
_SECTION = re.compile(r"(?:^|\n)\s*(qualifications?|requirements?|nice\s+to\s+have|preferred\s+skills|responsibilities|what\s+you['’]ll\s+do|our\s+stack)\s*:?\s*(?:\n|$)", re.I)
_NEGATIVE_CONTINUATION = re.compile(r"(?:[\s,()/\-:'\"’]|\b(?:and|or|any|a|an|the|our|their|production|internal|legacy|existing|currently|actively|actually|yet|tech)\b)*", re.I)
_SUBJECT_CHANGE = re.compile(r"\b(?:[\w.-]+\s+(?:uses|runs|operates|deploys|provides|offers|released|announced)|customers|clients|users|partners|while|although|whereas)\b", re.I)
_FIRST_PERSON_ACTION = re.compile(r"\bwe\s+(?:(?:do|did)\s+not\s+|(?:don['’]t|didn['’]t|currently|actively|already|also|still|never)\s+)*(?:use|used|run|ran|operate|maintain|manage|deploy|rely\s+on)\b", re.I)
_ELLIPTICAL_ACTIVE = re.compile(r"^\s*(?:(?:currently|actively|already|also|still)\s+)*(?:use|run|operate|maintain|manage|deploy|rely\s+on|monitor\s+with)\b", re.I)
_PRODUCT_SUBJECT = re.compile(r"\s+(?:customers?|clients?|users?|partners?|uses|runs|operates|deploys|provides|offers|released|announced|supports|enables|allows|requires|integrates)\b|\s+(?:is|are|was|were|has|have)\s+(?:a|an|the|published|announced|released|available)\b", re.I)


def _status(clause, match, matches, qualification_section, inherited_first_party=False):
    start, end = match.span()
    previous = next((item for item in reversed(matches) if item.end() <= start), None)
    following = next((item for item in matches if item.start() >= end), None)
    before = clause[:start]
    after = clause[end:]
    local_before = before[previous.end():] if previous else before
    local_after = after[:following.start() - end] if following else after
    negative = list(_NEGATION.finditer(before))
    affirmative = list(_ACTIVE.finditer(before))
    if inherited_first_party:
        affirmative.extend(_ELLIPTICAL_ACTIVE.finditer(before))
    negative_applies = negative and _NEGATIVE_CONTINUATION.fullmatch(_TECH.sub(" tech ", before[negative[-1].end():]))
    if negative_applies and (not affirmative or negative[-1].start() > affirmative[-1].start()):
        return "negated", 0.9
    if re.match(r"\s*(?:(?:is|are|was|were)\s+)?(?:not\s+(?:used|deployed|running|supported)|isn['’]t\s+used|wasn['’]t\s+used)\b", local_after, re.I):
        return "negated", 0.9
    historical = list(_HISTORICAL.finditer(before))
    if historical and (not affirmative or historical[-1].start() >= affirmative[-1].start()):
        return "historical", 0.8
    if re.match(r"\s*(?:(?:is|was|has\s+been)\s+)?(?:retired|decommissioned|discontinued)\b", local_after, re.I):
        return "historical", 0.8
    requirement = list(_REQUIREMENT.finditer(before))
    required_after = re.match(r"\s+(?:experience|knowledge|skills|expertise|proficiency|familiarity)(?:\s+(?:is|are))?\s*(?:required|preferred)?\b|\s+(?:is\s+)?(?:required|preferred)\b", local_after, re.I)
    is_requirement = bool(required_after or requirement and (not affirmative or requirement[-1].start() > affirmative[-1].start()))
    if (previous and re.fullmatch(r"\s*(?:,\s*)?or\s+(?:equivalent\s+)?", local_before, re.I)
            or following and re.fullmatch(r"\s*(?:,\s*)?or\s+(?:equivalent\s+)?", local_after, re.I)):
        return "alternative", 0.35
    if is_requirement:
        return "requirement", 0.45
    migration = _MIGRATION.search(clause)
    if migration and re.search(r"\b(?:we|our)\b", clause[:migration.end() + 60], re.I):
        connector = re.search(r"\b(?:to|into|onto|with)\b", clause[migration.end():], re.I)
        if connector:
            target_start = migration.end() + connector.end()
            completed = migration.group().casefold() in {"migrated", "moved", "replaced"}
            if start >= target_start:
                return ("asserted_use", 0.85) if completed else ("planned", 0.65)
            if start >= migration.end() or start < migration.start() and re.search(r"\breplac", migration.group(), re.I):
                return ("historical", 0.8) if completed else ("asserted_use", 0.8)
    planned = list(_PLANNED.finditer(before))
    if planned and (not affirmative or planned[-1].start() >= affirmative[-1].start()):
        return "planned", 0.65
    if re.match(r"\s+(?:(?:rollout|deployment|adoption)\s+)?(?:is\s+)?(?:planned|proposed|under\s+evaluation)\b", local_after, re.I):
        return "planned", 0.65
    if qualification_section and not affirmative:
        return "requirement", 0.45
    if _PRODUCT_SUBJECT.match(local_after):
        return "mention", 0.4
    third_party = re.search(r"\b(?:our\s+(?:customers?|clients?|users?|partners?)|we\s+(?:help|enable|support|teach|advise)\b|customer\s+case\s+study)\b", before, re.I)
    if not third_party:
        if affirmative and not _SUBJECT_CHANGE.search(before[affirmative[-1].end():]):
            return "asserted_use", 0.9
        if re.search(r"\bour\s+(?:(?:production|internal|existing|managed|corporate|enterprise|global|current)\s+){0,3}$", before, re.I):
            if re.match(r"\s*(?:\d[\w.]*\s+)?(?:clusters?|fleet|deployment|environment|servers?|installation|infrastructure|instances?|databases?|platform|directory|tenant|endpoints?|devices?|estate|firewalls?|appliances?|systems?|pipeline|setup|stack)\b", after, re.I):
                return "asserted_use", 0.9
        if re.search(r"\b(?:operate|maintain|manage|run|support|administer)\s+our\s+(?:[\w-]+\s+){0,2}$", before, re.I):
            return "asserted_use", 0.9
    return "mention", 0.4


def extract(text, *, source_type=""):
    text = str(text or "")[:TEXT_LIMIT]
    boundaries = [(match.start(), match.end()) for match in _BOUNDARY.finditer(text)]
    findings = []
    seen = set()
    cursor = 0
    last = 0
    for match in _TECH.finditer(text):
        while cursor < len(boundaries) and boundaries[cursor][1] <= match.start():
            last = boundaries[cursor][1]
            cursor += 1
        stop = boundaries[cursor][0] if cursor < len(boundaries) else len(text)
        left = max(last, match.start() - 1200)
        right = min(stop, match.end() + 1200)
        clause = text[left:right]
        local_matches = list(_TECH.finditer(clause))
        local_match = next(item for item in local_matches if item.start() == match.start() - left)
        qualification_section = False
        if re.search(r"job|greenhouse|lever|ashby|career|ats", str(source_type), re.I):
            sections = list(_SECTION.finditer(text[max(0, left - 4000):match.start()]))
            qualification_section = bool(sections and not re.match(r"responsibilities|what|our", sections[-1].group(1), re.I))
        inherited_first_party = False
        if cursor and text[boundaries[cursor - 1][0]:last].casefold() == "but" and left == last:
            previous_start = boundaries[cursor - 2][1] if cursor > 1 else 0
            previous_clause = text[previous_start:boundaries[cursor - 1][0]]
            subjects = list(_FIRST_PERSON_ACTION.finditer(previous_clause))
            inherited_first_party = bool(subjects and not _SUBJECT_CHANGE.search(previous_clause[subjects[-1].end():]))
        status, confidence = _status(clause, local_match, local_matches, qualification_section, inherited_first_party)
        vendor, vendor_name, product, product_name, category, part = _PRODUCTS[match.lastgroup]
        version_match = _VERSION.match(text[match.end():min(right, match.end() + 50)])
        version = version_match.group(1) if version_match else ""
        snippet_left = max(0, local_match.start() - (SNIPPET_LIMIT - len(match.group())) // 2)
        snippet = clause[snippet_left:snippet_left + SNIPPET_LIMIT].strip()
        identity = (product_name, version, snippet, status)
        if identity in seen:
            continue
        seen.add(identity)
        findings.append({"vendor": normalize(vendor), "product": normalize(product), "product_name": product_name,
                         "vendor_name": vendor_name, "category": category, "part": part, "version": version,
                         "cpe": None, "evidence_snippet": snippet, "status": status,
                         "confidence": confidence, "method": METHOD})
        if len(findings) >= FINDING_LIMIT:
            break
    return findings
