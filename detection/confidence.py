from utils.helpers import (
    get_random_confidence,
    get_random_confidence_on_xss,
    get_random_confidence_on_match,
)

def calculate_confidence(xs_scan: int, xs_match: int) -> float:
    confidence = get_random_confidence()
    confidence_after_scan = get_random_confidence_on_xss() if xs_scan else 0.0
    confidence_after_match = get_random_confidence_on_match() if xs_match else 0.0

    final_confidence = confidence + confidence_after_scan + confidence_after_match
    return round(final_confidence, 2)
