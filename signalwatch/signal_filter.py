import re
from collections import Counter
from functools import lru_cache


@lru_cache(maxsize=128)
def _rules(terms):
    return tuple((term, re.compile(r"(?<![\w])" + r"\s+".join(re.escape(part) for part in term.split()) + r"(?![\w])", re.I)) for term in terms)


def qualify_signal(text, products, indicators):
    products = tuple(dict.fromkeys(value.strip() for value in products if isinstance(value, str) and value.strip()))
    indicators = tuple(dict.fromkeys(value.strip() for value in indicators if isinstance(value, str) and value.strip()))
    text = str(text or "")
    matched_products = [term for term, rule in _rules(products) if rule.search(text)]
    matched_indicators = [term for term, rule in _rules(indicators) if rule.search(text)]
    reasons = []
    if not matched_products:
        reasons.append("product_identifier_missing")
    if not matched_indicators:
        reasons.append("exploit_or_patch_indicator_missing")
    return {"qualified": bool(matched_products and matched_indicators), "matched_products": matched_products,
            "matched_indicators": matched_indicators, "reasons": reasons, "method": "literal_keywords_v1"}


def filter_signals(records, products, indicators, text_fields=("title", "summary", "text")):
    qualified, filtered, reasons = [], [], Counter()
    for record in records:
        result = qualify_signal(" ".join(str(record.get(field) or "") for field in text_fields), products, indicators)
        value = {**record, "_signal": result}
        (qualified if result["qualified"] else filtered).append(value)
        reasons.update(result["reasons"])
    return {"qualified": qualified, "filtered": filtered, "reason_counts": dict(reasons),
            "counts": {"records": len(qualified) + len(filtered), "qualified": len(qualified), "filtered": len(filtered)}}
