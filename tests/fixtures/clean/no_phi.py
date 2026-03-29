# Synthetic clean fixture: Benign algorithm code — zero PHI expected
# Contains only mathematical logic, generic variable names approved by CLAUDE.md,
# and unambiguous non-PHI strings. Must produce zero findings on any detector.
# Expected findings: 0

import math


def calculate_circle_area(radius: float) -> float:
    """Return area of a circle given its radius."""
    return math.pi * radius**2


def calculate_fibonacci_sequence(term_count: int) -> list[int]:
    """Return the first term_count terms of the Fibonacci sequence."""
    if term_count <= 0:
        return []
    sequence = [0, 1]
    while len(sequence) < term_count:
        sequence.append(sequence[-1] + sequence[-2])
    return sequence[:term_count]


SPEED_OF_LIGHT_M_PER_S = 299_792_458
GRAVITATIONAL_CONSTANT = 6.674e-11
AVOGADRO_NUMBER = 6.022e23

STATUS_PENDING = "pending"
STATUS_COMPLETE = "complete"
STATUS_FAILED = "failed"

RETRY_LIMIT = 3
TIMEOUT_SECONDS = 30
MAX_BATCH_SIZE = 100
