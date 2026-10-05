"""Compare two captured byte streams to find which bytes carry which input.

Reverse engineering works by controlled experiments: print a blank label, then a label with one dot, and see
which bytes changed. These helpers answer that without reading hex by eye.
"""

from __future__ import annotations

from typing import Any

MAX_DIFF_BYTES = 4 * 1024 * 1024


def _hex(data: bytes, limit: int) -> str:
    text = data[:limit].hex(" ")
    return text + (" ..." if len(data) > limit else "")


def diff_streams(a: bytes, b: bytes, *, max_ranges: int = 40, preview_bytes: int = 32) -> dict[str, Any]:
    """Report how two streams differ.

    Same length: the changed byte ranges. Different length: the shared prefix and suffix and the differing middle
    (the usual shape of "same header, different payload"). Positional ranges are not meaningful across a length
    change, which is why they are only reported for equal lengths.
    """
    if len(a) > MAX_DIFF_BYTES or len(b) > MAX_DIFF_BYTES:
        raise ValueError(f"streams over {MAX_DIFF_BYTES} bytes are not diffed")
    prefix = 0
    limit = min(len(a), len(b))
    while prefix < limit and a[prefix] == b[prefix]:
        prefix += 1
    suffix = 0
    while suffix < limit - prefix and a[len(a) - 1 - suffix] == b[len(b) - 1 - suffix]:
        suffix += 1

    result: dict[str, Any] = {
        "length_a": len(a),
        "length_b": len(b),
        "identical": a == b,
        "common_prefix": prefix,
        "common_suffix": suffix,
    }
    if a == b:
        return result

    if len(a) == len(b):
        ranges, start = [], None
        for i in range(len(a)):
            if a[i] != b[i]:
                if start is None:
                    start = i
            elif start is not None:
                ranges.append((start, i))
                start = None
        if start is not None:
            ranges.append((start, len(a)))
        result["changed_bytes"] = sum(end - begin for begin, end in ranges)
        result["ranges"] = [
            {
                "offset": begin,
                "length": end - begin,
                "a": _hex(a[begin:end], preview_bytes),
                "b": _hex(b[begin:end], preview_bytes),
            }
            for begin, end in ranges[:max_ranges]
        ]
        result["ranges_truncated"] = len(ranges) > max_ranges
    else:
        mid_a, mid_b = a[prefix : len(a) - suffix], b[prefix : len(b) - suffix]
        result["middle"] = {
            "offset": prefix,
            "length_a": len(mid_a),
            "length_b": len(mid_b),
            "a": _hex(mid_a, preview_bytes),
            "b": _hex(mid_b, preview_bytes),
        }
    return result


def diff_transfers(a: list[bytes], b: list[bytes], *, max_items: int = 40, preview_bytes: int = 24) -> dict[str, Any]:
    """Compare two captures transfer by transfer (same index in each)."""
    differing = []
    for i in range(max(len(a), len(b))):
        left, right = (a[i] if i < len(a) else None), (b[i] if i < len(b) else None)
        if left == right:
            continue
        differing.append(
            {
                "transfer": i,
                "length_a": None if left is None else len(left),
                "length_b": None if right is None else len(right),
                "a": None if left is None else _hex(left, preview_bytes),
                "b": None if right is None else _hex(right, preview_bytes),
            }
        )
    return {
        "transfers_a": len(a),
        "transfers_b": len(b),
        "differing": len(differing),
        "items": differing[:max_items],
        "items_truncated": len(differing) > max_items,
    }
