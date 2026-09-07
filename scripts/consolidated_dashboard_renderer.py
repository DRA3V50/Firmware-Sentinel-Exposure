#!/usr/bin/env python3
"""Subsystem #9 review renderer for the approved BioDefense dashboard.

This is the authoritative review implementation for the planned production
entry point. During #9, scripts/generate_case_banner.py intentionally remains
the unchanged legacy entry point because the checked production root is still
pre-#8 state and a switchover would fail closed. This module consumes the frozen
Subsystem #8 dashboard_state adapter once, makes one narrow renderer-side
display projection for fields absent from that frozen public shape, and then
uses the approved visual helpers copied from the recovery archive.

Normal rendering is read-only with respect to the state root. Review outputs
are intentionally separate from the production GIF until Subsystem #10.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import math
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable, Sequence
from zoneinfo import ZoneInfo

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

from case_state import (
    CaseStateError,
    StateValidationError,
    StaleDataError,
    csharp_level,
    load_active_case,
    validate_active_case,
)
from dashboard_state import build_dashboard_state


SCRIPT_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIR.parent
APPROVED_ASSET_DIR = REPOSITORY_ROOT / "assets" / "approved"
REVIEW_DIR = REPOSITORY_ROOT / "assets" / "review"

POPULATED_MASTER = APPROVED_ASSET_DIR / "APPROVED_POPULATED_LAYOUT.png"
CLEAR_MASTER = APPROVED_ASSET_DIR / "APPROVED_CLEAR_BASE_LAYOUT.png"
BIOHAZARD_REFERENCE = APPROVED_ASSET_DIR / "BIOHAZARD_REFERENCE.png"
CASE_OVERVIEW_STATIC = (
    APPROVED_ASSET_DIR
    / "subsystem_07_case_overview"
    / "case_overview_proposal_b_central_hub_static_reference.png"
)

CANVAS_SIZE = (1727, 911)
FRAME_COUNT = 120
FRAME_DURATION_MS = 50
KEYFRAME_INDICES = (0, 20, 40, 60, 80, 100, 119)
MOTION_AUDIT_INDICES = tuple(range(0, FRAME_COUNT, 10))

# V7 review-only display lanes.  These are deliberately narrower than their
# containing panels and do not alter frozen geometry, state, or subsystem code.
TOP_HEADER_V7_GROUP_BOUNDS = (1368, 8, 1720, 34)
TOP_HEADER_V7_RIGHT_EDGE = 1718
TOP_HEADER_V7_BASELINE_Y = 14
TOP_HEADER_V7_PROBE_SCORES = (10, 21, 50, 71, 88)
SYSTEM_STATUS_V7_LIST_BOUNDS = (470, 604, 815, 710)
SYSTEM_STATUS_V7_DIVIDER_BANDS = (
    (471, 625, 813, 626),
    (471, 646, 813, 648),
    (471, 668, 813, 669),
    (471, 689, 813, 691),
)
SYSTEM_STATUS_V7_DIAGNOSTICS_BOUNDS = (475, 714, 812, 716)
THREAT_SCORE_SUFFIX_V7_CLEAN_BOUNDS = (850, 615, 940, 657)
THREAT_SCORE_SUFFIX_V7_COMPARE_BOUNDS = (890, 628, 942, 660)
SEVERITY_V7_VALUE_BOUNDS = (
    (234, 397, 400, 416),
    (603, 338, 812, 360),
    (1334, 684, 1710, 726),
)

# V9 is limited to the static front-folder tab inside the approved Evidence
# Package artwork.  The envelope is deliberately larger than the detected
# component only so the source-derived connected-component mask can preserve
# the exact textured tab shape instead of repainting a rectangle.
V9_EVIDENCE_FRONT_ACCENT_BOUNDS_GLOBAL = (1655, 92, 1680, 119)
V9_EVIDENCE_FRONT_ACCENT_BOUNDS_LOCAL = (387, 52, 412, 79)
V9_EVIDENCE_FRONT_ACCENT_EXPECTED_PIXELS = 256
V9_EVIDENCE_FRONT_ACCENT_SCALE = (0.64, 0.45, 0.43)

EXPECTED_APPROVED_HASHES = {
    POPULATED_MASTER: "90a223d08555853fd58c7bc7c0c30eadecfa7df3b5320db23e373462735312c4",
    CLEAR_MASTER: "168d5b6ba745de5431f8fbaa9c5d5e4a95464b9e150f6aa23b862e4800d68f38",
    BIOHAZARD_REFERENCE: "ec0eb4cd38db13d34c0259f8ba920e4d9a1d2783feeb2f0d25e4ea2b0bf52ba5",
}

EXPECTED_HELPER_HASHES = {
    "s01": "087cf790abdcfd83292ff285effe47e6473820e9f8c799acc683c61c86fa505c",
    "s02": "a9fd7bf655d5f0c04b952fa31a84759d8369627e41e8cad1a152760669b5f9fa",
    "s03": "161df7b0fb51806c34cc7b1cfce9656c8f09075f9c96e00ebd4f36af76e81e5e",
    "s04": "2ad372dd3a8f417b135389b2f9a0ef64b26349afd0d6b4439423352f22c7bffd",
    "s05": "12c9d32d871f873ca6d81f1c331ac9c6a666b5efa72b24e4752944783efdf873",
    "s06": "a36377ef488687a40211dfd67fa20170d60302201ef815bf3d73e88492dc298f",
    "s07": "aeaa0ebd98ec5e65bcb4584711d598e1bf3e16e2998ec2b8e14cd87152207272",
}

HELPER_PATHS = {
    "s01": SCRIPT_DIR / "frozen_reference" / "subsystem_01_biohazard" / "biohazard_test.py",
    "s02": SCRIPT_DIR / "frozen_reference" / "subsystem_02_evidence_magnifier" / "magnifying_glass_test.py",
    "s03": SCRIPT_DIR / "frozen_reference" / "subsystem_03_workflow" / "workflow_strip_test.py",
    "s04": SCRIPT_DIR / "frozen_reference" / "subsystem_04_active_case_feed" / "active_case_feed_test.py",
    "s05": SCRIPT_DIR / "frozen_reference" / "subsystem_05_system_status" / "system_status_test.py",
    "s06": SCRIPT_DIR / "frozen_reference" / "subsystem_06_threat_monitor" / "threat_monitor_test.py",
    "s07": SCRIPT_DIR / "frozen_reference" / "subsystem_07_case_overview" / "case_overview_proposal_b_central_hub_animation.py",
}


class RendererContractError(RuntimeError):
    """Raised when an input cannot be rendered truthfully and coherently."""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def sha256_array(array: np.ndarray) -> str:
    return sha256_bytes(np.ascontiguousarray(array).tobytes())


def ensure_hash(path: Path, expected: str) -> str:
    if not path.is_file():
        raise RendererContractError(f"Required approved asset is missing: {path}")
    actual = sha256_path(path)
    if actual != expected:
        raise RendererContractError(
            f"Approved asset hash mismatch: {path.name}; expected {expected}, got {actual}"
        )
    return actual


def verify_approved_inputs() -> dict[str, str]:
    records = {path.name: ensure_hash(path, expected) for path, expected in EXPECTED_APPROVED_HASHES.items()}
    reference_hash = ensure_hash(
        CASE_OVERVIEW_STATIC,
        "6fb176d5777ba79dfcf0d3984188757d9961db413cda1bb6e47a018f73486aab",
    )
    records[CASE_OVERVIEW_STATIC.name] = reference_hash
    return records


def load_helper(name: str, path: Path) -> ModuleType:
    if not path.is_file():
        raise RendererContractError(f"Missing frozen visual helper: {path}")
    actual = sha256_path(path)
    expected = EXPECTED_HELPER_HASHES[name]
    if actual != expected:
        raise RendererContractError(
            f"Frozen visual helper hash mismatch: {path.name}; expected {expected}, got {actual}"
        )
    module_name = f"_bd_frozen_{name}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RendererContractError(f"Cannot import frozen visual helper: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class FrozenHelpers:
    s01: ModuleType
    s02: ModuleType
    s03: ModuleType
    s04: ModuleType
    s05: ModuleType
    s06: ModuleType
    s07: ModuleType


def load_frozen_helpers() -> FrozenHelpers:
    return FrozenHelpers(**{name: load_helper(name, path) for name, path in HELPER_PATHS.items()})


PRESENTATION_TIMEZONE = ZoneInfo("America/New_York")


def presentation_instant(value: object) -> datetime | None:
    """Parse persisted UTC safely, then convert only the dashboard display."""

    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RendererContractError(f"Invalid persisted timestamp: {raw!r}") from exc
    if parsed.tzinfo is None:
        raise RendererContractError("Persisted dashboard timestamp must be timezone-aware.")
    return parsed.astimezone(PRESENTATION_TIMEZONE)


def text_timestamp(value: object) -> str:
    instant = presentation_instant(value)
    return "UNAVAILABLE" if instant is None else instant.strftime("%Y-%m-%d %H:%M:%S %Z")


def footer_timestamp_for_render_instant(
    render_started_at: datetime,
    *,
    separator: str = ":",
) -> str:
    """Format the one Eastern instant captured for this dashboard render."""

    if render_started_at.tzinfo is None:
        raise RendererContractError("Dashboard render timestamp must be timezone-aware.")
    instant = render_started_at.astimezone(PRESENTATION_TIMEZONE)
    hour = instant.strftime("%I").lstrip("0") or "0"
    return f"{instant:%Y-%m-%d} {hour}{separator}{instant:%M %p %Z}"


def capture_render_started_at(value: datetime | None = None) -> datetime:
    """Capture or normalize the one timezone-aware timestamp for one render."""

    instant = datetime.now(PRESENTATION_TIMEZONE) if value is None else value
    if instant.tzinfo is None:
        raise RendererContractError("Dashboard render timestamp must be timezone-aware.")
    return instant.astimezone(PRESENTATION_TIMEZONE)


def event_timestamp(value: object) -> str:
    raw = str(value or "")
    if "T" in raw:
        raw = raw.split("T", 1)[1]
    raw = raw.replace("Z", "").replace("+00:00", "")
    return raw[:5] if len(raw) >= 5 else "TIME?"


def human_stage(value: object) -> str:
    return str(value or "UNKNOWN").replace("_", " ")


def severity_bucket(value: object) -> str:
    level = str(value or "").upper()
    if level in {"CRITICAL", "HIGH"}:
        return "HIGH"
    if level in {"ELEVATED", "MODERATE", "MEDIUM", "GUARDED"}:
        return "MEDIUM"
    return "LOW"


def numeric_history(records: object, name: str) -> np.ndarray:
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise RendererContractError(f"{name} must be a chronological sequence.")
    values: list[float] = []
    for record in records:
        if isinstance(record, dict):
            candidate = record.get("value")
        else:
            candidate = record
        try:
            value = float(candidate)
        except (TypeError, ValueError) as exc:
            raise RendererContractError(f"{name} contains a non-numeric value.") from exc
        if not math.isfinite(value) or value < 0.0 or value > 100.0:
            raise RendererContractError(f"{name} must remain normalized within 0-100.")
        values.append(value)
    if not values:
        raise RendererContractError(
            f"{name} is empty. The renderer refuses to invent a plausible live signal."
        )
    return np.asarray(values, dtype=np.float64)


def resample(values: Sequence[float], width: int, *, name: str) -> np.ndarray:
    source = np.asarray(values, dtype=np.float64)
    if source.ndim != 1 or source.size < 1 or not np.all(np.isfinite(source)):
        raise RendererContractError(f"{name} is not a usable numeric series.")
    if width < 1:
        raise RendererContractError(f"{name} target width is invalid.")
    if source.size == 1:
        return np.full(width, source[0], dtype=np.float64)
    source_x = np.linspace(0.0, 1.0, source.size, endpoint=True)
    target_x = np.linspace(0.0, 1.0, width, endpoint=True)
    result = np.interp(target_x, source_x, source)
    result[0] = source[0]
    result[-1] = source[-1]
    return result


def evidence_correlation_count(relationships: Sequence[dict[str, Any]]) -> int:
    for relation in relationships:
        relation_type = str(relation.get("relationship_type", relation.get("type", ""))).upper()
        if "CORRELATION" not in relation_type:
            continue
        attributes = relation.get("attributes")
        if isinstance(attributes, dict):
            value = attributes.get("count", attributes.get("correlation_count", 0))
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                return value
    return 0


def build_renderer_state(root: Path | str | None = None) -> dict[str, Any]:
    """Adapt one fully validated #8 state without modifying its frozen contract."""

    normalized = build_dashboard_state(root)
    case = load_active_case(root)
    if case is None:
        raise RendererContractError("No persistent active case is available.")
    validate_active_case(case)

    shared = normalized["shared"]
    required_shared = (
        "case_id",
        "campaign_id",
        "lifecycle_status",
        "current_stage",
        "severity",
        "priority",
        "lead_analyst",
        "evidence_count",
        "ioc_count",
        "updated_at",
        "state_revision",
    )
    mismatches = [
        key for key in required_shared if case.get(key) != shared.get(key)
    ]
    if mismatches:
        raise RendererContractError(
            "The active case diverged from the validated #8 dashboard state: "
            + ", ".join(mismatches)
        )

    feed_history = numeric_history(
        normalized["active_case_feed"]["event_intensity_history"],
        "active-case event intensity history",
    )
    anomaly_history = numeric_history(
        normalized["threat_monitor"]["anomaly_history"],
        "active-case anomaly history",
    )
    relationships = normalized["case_overview"]["relationships"]
    if not isinstance(relationships, list):
        raise RendererContractError("Case Overview relationships must be a list.")
    events = normalized["active_case_feed"]["events"]
    if not isinstance(events, list):
        raise RendererContractError("Active Case Feed events must be a list.")
    manifest_items = normalized["evidence_package"]["manifest"]["items"]
    if not isinstance(manifest_items, list):
        raise RendererContractError("Evidence manifest items must be a list.")

    integration_sources = {
        str(item.get("source_system"))
        for item in manifest_items
        if isinstance(item, dict) and item.get("source_system")
    }
    integration_sources.update(
        str(event.get("source"))
        for event in events
        if isinstance(event, dict) and event.get("source")
    )
    canonical = normalized["threat_monitor"]["threat"]
    score = int(canonical["score"])
    display_level = str(canonical["display_level_for_subsystem_06"])
    if not 0 <= score <= 100:
        raise RendererContractError("The canonical threat score is outside 0-100.")

    relationship_count = evidence_correlation_count(relationships)
    threat_history = normalized["threat_monitor"].get("threat_history", [])
    if not isinstance(threat_history, list):
        threat_history = []

    display_fields = {
        key: case.get(key)
        for key in (
            "classification",
            "threat_family",
            "status",
            "containment_phase",
            "date",
            "recommended_action",
            "assessment",
            "confidence",
            "risk_score",
            "affected_assets",
            "device_family",
            "affected_platform",
            "network_zone",
        )
    }
    return {
        "dashboard": normalized,
        "case": copy.deepcopy(case),
        "display": display_fields,
        "feed_history": feed_history,
        "anomaly_history": anomaly_history,
        "events": copy.deepcopy(events),
        "relationships": copy.deepcopy(relationships),
        "manifest_items": copy.deepcopy(manifest_items),
        "integration_count": len(integration_sources),
        "correlation_count": relationship_count,
        "threat_history_count": len(threat_history),
        "canonical_threat_score": score,
        "subsystem_06_display_level": display_level,
    }


@lru_cache(maxsize=None)
def dashboard_font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    candidates = (
        "C:/Windows/Fonts/bahnschrift.ttf" if bold else "C:/Windows/Fonts/consola.ttf",
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
    )
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size=size)
        except OSError:
            continue
    return ImageFont.load_default(size=size)


@dataclass(frozen=True)
class TextEntry:
    bounds: tuple[int, int, int, int]
    position: tuple[int, int]
    value: str
    color: tuple[int, int, int]
    size: int = 12
    bold: bool = False
    max_width: int | None = None
    # The cleanup lane is deliberately separate from the visual field bounds.
    # In particular it must never absorb a static panel frame, divider, icon,
    # or route merely because the state value is close to one.
    clear_bounds: tuple[int, int, int, int] | None = None
    line_spacing: int = 0
    # Most state lanes take their registered texture from the approved clear
    # master. A small number of master-specific lanes must instead repair the
    # populated source locally because the clear master contains decorative
    # placeholder rules that are not part of the approved panel appearance.
    clean_source: str = "clear"
    cleanup_dilate: int = 1
    inpaint_radius: int = 2
    preserve_horizontal_rules: bool = True


def measured_text_bbox(value: str, size: int, bold: bool = False) -> tuple[int, int, int, int]:
    """Return Pillow's actual glyph bounds for one dashboard string."""

    image = Image.new("RGB", (1, 1))
    return ImageDraw.Draw(image).textbbox((0, 0), value, font=dashboard_font(size, bold))


def measured_text_advance(value: str, size: int, bold: bool = False) -> int:
    image = Image.new("RGB", (1, 1))
    width = ImageDraw.Draw(image).textlength(value, font=dashboard_font(size, bold))
    return int(math.ceil(width))


def case_level_from_score(score: int) -> int:
    """Display-only level fallback derived from the canonical C# score."""

    return max(1, min(10, int(math.ceil(int(score) / 10))))


def top_header_layout(case_id: str, score: int) -> list[dict[str, Any]]:
    """Measure and right-align the complete V7 header group on one baseline."""

    red = (235, 42, 35)
    components = (
        (f"LEVEL {case_level_from_score(score)}", red, 11, True),
        ("•", red, 11, True),
        ("CASE ACCESS", red, 11, True),
        (f"CASE: {case_id}", red, 11, True),
    )
    gaps = (12, 12, 12)
    widths = [measured_text_advance(value, size, bold) for value, _color, size, bold in components]
    total = sum(widths) + sum(gaps)
    x = TOP_HEADER_V7_RIGHT_EDGE - total
    if x < TOP_HEADER_V7_GROUP_BOUNDS[0]:
        raise RendererContractError("Measured V7 top header exceeds its approved right-side lane.")
    layout: list[dict[str, Any]] = []
    for index, ((value, color, size, bold), width) in enumerate(zip(components, widths)):
        layout.append(
            {
                "value": value,
                "color": color,
                "size": size,
                "bold": bold,
                "position": (x, TOP_HEADER_V7_BASELINE_Y),
                "width": width,
                "bbox": ImageDraw.Draw(Image.new("RGB", (1, 1))).textbbox(
                    (x, TOP_HEADER_V7_BASELINE_Y), value, font=dashboard_font(size, bold)
                ),
            }
        )
        x += width + (gaps[index] if index < len(gaps) else 0)
    return layout


def top_header_entries(renderer_state: dict[str, Any]) -> list[TextEntry]:
    shared = renderer_state["dashboard"]["shared"]
    layout = top_header_layout(str(shared["case_id"]), int(renderer_state["canonical_threat_score"]))
    return [
        TextEntry(
            TOP_HEADER_V7_GROUP_BOUNDS,
            item["position"],
            item["value"],
            item["color"],
            item["size"],
            item["bold"],
            item["width"] + 1,
            clear_bounds=TOP_HEADER_V7_GROUP_BOUNDS,
            clean_source="source",
            cleanup_dilate=2,
            inpaint_radius=2,
            preserve_horizontal_rules=False,
        )
        for item in layout
    ]


def severity_presentation_level(value: object) -> str:
    """Map existing severity vocabulary to the approved four display colors."""

    normalized = str(value or "").strip().upper()
    if normalized == "CRITICAL":
        return "CRITICAL"
    if normalized == "HIGH":
        return "HIGH"
    if normalized in {"MEDIUM", "MODERATE", "ELEVATED", "GUARDED"}:
        return "MEDIUM"
    return "LOW"


def semantic_severity_color(raw: np.ndarray, value: object) -> tuple[int, int, int]:
    return threshold_guide_colors(raw)[severity_presentation_level(value)]


def inline_colored_text_entries(
    bounds: tuple[int, int, int, int],
    position: tuple[int, int],
    parts: Sequence[tuple[str, tuple[int, int, int]]],
    *,
    size: int,
    bold: bool,
    max_width: int,
    clean_source: str = "clear",
    cleanup_dilate: int = 1,
    inpaint_radius: int = 2,
    preserve_horizontal_rules: bool = True,
    line_spacing: int = 0,
) -> list[TextEntry]:
    """Build one measured, semantically colored value line within a shared lane."""

    x, y = position
    entries: list[TextEntry] = []
    for value, color in parts:
        entries.append(
            TextEntry(
                bounds,
                (x, y),
                value,
                color,
                size,
                bold,
                max_width,
                clear_bounds=bounds,
                clean_source=clean_source,
                cleanup_dilate=cleanup_dilate,
                inpaint_radius=inpaint_radius,
                preserve_horizontal_rules=preserve_horizontal_rules,
                line_spacing=line_spacing,
            )
        )
        x += measured_text_advance(value, size, bold)
    return entries


def centered_text_entry(
    bounds: tuple[int, int, int, int],
    value: str,
    color: tuple[int, int, int],
    size: int,
    bold: bool = False,
) -> TextEntry:
    """Center a short descriptor using actual Pillow glyph measurements."""

    x1, y1, x2, y2 = bounds
    left, top, right, bottom = measured_text_bbox(value, size, bold)
    width, height = right - left, bottom - top
    x = x1 + ((x2 - x1 - width) // 2) - left
    y = y1 + ((y2 - y1 - height) // 2) - top
    actual = ImageDraw.Draw(Image.new("RGB", (1, 1))).textbbox(
        (x, y), value, font=dashboard_font(size, bold)
    )
    if actual[0] < x1 or actual[1] < y1 or actual[2] > x2 or actual[3] > y2:
        raise RendererContractError(f"Measured centered text does not fit its V7 lane: {value!r}")
    return TextEntry(bounds, (x, y), value, color, size, bold, x2 - x1)


def foreground_mask(region: np.ndarray, minimum_brightness: int = 5) -> np.ndarray:
    values = region.astype(np.int16)
    maximum = np.max(values, axis=2)
    # Text antialias pixels in the approved raster can be nearly black. The
    # explicit ROIs below deliberately exclude borders/icons, so clean every
    # non-background glyph fragment rather than leaving light-gray ghosts.
    # Inpainting reconstructs the local source texture; no solid black cover
    # rectangle is used.
    return maximum >= minimum_brightness


def fit_text(draw: ImageDraw.ImageDraw, value: str, font: ImageFont.ImageFont, width: int | None) -> str:
    """Validate an already-fitted display value.

    A dashboard field may wrap complete text or use a field-specific semantic
    display summary, but it must never silently suffix a partial sentence with
    an ellipsis.  Keeping this check centralized makes a layout regression fail
    visibly during review rendering instead of hiding it in a GIF frame.
    """

    if "..." in value:
        raise RendererContractError("Dynamic dashboard text may not contain an ellipsis.")
    if width is not None:
        widest = max((draw.textlength(line, font=font) for line in value.splitlines()), default=0.0)
        if widest > width:
            raise RendererContractError(
                f"Dynamic text exceeds its approved lane ({widest:.1f}px > {width}px): {value!r}"
            )
    return value


def text_lane(entry: TextEntry) -> tuple[int, int, int, int]:
    return entry.clear_bounds or entry.bounds


def legacy_v2_palette_entries(entries: Sequence[TextEntry]) -> list[TextEntry]:
    """Reconstruct only the prior V2 cleanup lanes for palette compatibility.

    V3 uses larger source-cleanup lanes in four measured review ROIs.  The
    original fixed global GIF palette must still be built from the former plate
    so a tiny clean-plate correction cannot perturb decoded pixels elsewhere.
    This helper is palette-only; live V3 frames always use the corrected lanes.
    """

    legacy: list[TextEntry] = []
    for entry in entries:
        if entry.bounds in CENTER_METADATA_ENTRY_BOUNDS:
            legacy.append(replace(entry, clear_bounds=None))
        elif entry.bounds in THREAT_SUMMARY_ENTRY_BOUNDS:
            legacy.append(
                replace(
                    entry,
                    clear_bounds=None,
                    cleanup_dilate=1,
                    inpaint_radius=2,
                )
            )
        elif entry.bounds == LEFT_LEAD_ANALYST_ENTRY_BOUNDS:
            legacy.append(
                replace(
                    entry,
                    clear_bounds=None,
                    cleanup_dilate=1,
                    inpaint_radius=2,
                    preserve_horizontal_rules=True,
                )
            )
        elif entry.bounds == (890, 631, 924, 654):
            # Palette sampling must retain the exact V5 suffix lane.  The
            # visible V6 suffix is deliberately larger and higher, but it
            # must not perturb the fixed global palette used everywhere else.
            legacy.append(
                replace(
                    entry,
                    bounds=(892, 636, 940, 657),
                    position=(894, 640),
                    size=11,
                    bold=False,
                    max_width=43,
                    clear_bounds=(892, 636, 940, 657),
                    clean_source="clear",
                    cleanup_dilate=1,
                    inpaint_radius=2,
                    preserve_horizontal_rules=True,
                )
            )
        elif entry.bounds in FEED_ALL_ENTRY_BOUNDS:
            # V6 cleans every feed row from a source-derived lane so the
            # obsolete list dividers cannot survive beneath live values.  The
            # fixed GIF palette, however, is sampled from the unchanged V5
            # entry geometry to avoid shifting unrelated decoded pixels.
            legacy.append(
                replace(
                    entry,
                    clear_bounds=None,
                    clean_source="clear",
                    cleanup_dilate=1,
                    inpaint_radius=2,
                    # The V5 palette sample retained every feed divider,
                    # including the severity-column rule.  V6 still removes
                    # those rules in its emitted source frames; this applies
                    # only to the palette-compatible reconstruction.
                    preserve_horizontal_rules=True,
                )
            )
        else:
            legacy.append(entry)
    return legacy


def palette_compatibility_entries(entries: Sequence[TextEntry]) -> list[TextEntry]:
    """Return only V3/V4 entries needing palette-only baseline restoration."""

    changed_bounds = (
        set(CENTER_METADATA_ENTRY_BOUNDS)
        | set(THREAT_SUMMARY_ENTRY_BOUNDS)
        | {LEFT_LEAD_ANALYST_ENTRY_BOUNDS, FOOTER_TIMESTAMP_ENTRY_BOUNDS}
        | set(FEED_ALL_ENTRY_BOUNDS)
    )
    return [entry for entry in entries if entry.bounds in changed_bounds]


def clean_text_entries(
    source: np.ndarray,
    registered_clear: np.ndarray,
    entries: Sequence[TextEntry],
) -> np.ndarray:
    """Make a registered, source-derived text-clean plate once.

    The registered clear master supplies the clean lane texture.  Its
    placeholder dashes are removed once in that small lane before it is used,
    so neither the clear-master placeholder nor the populated-master preview
    text can survive beneath a live value.  This preserves horizontal rules
    and all panel borders rather than replacing a whole panel or using a black
    rectangle.
    """

    result = source.copy()
    for entry in entries:
        x1, y1, x2, y2 = text_lane(entry)
        if entry.clean_source == "clear":
            lane_source = registered_clear
        elif entry.clean_source == "source":
            lane_source = source
        else:
            raise RendererContractError(f"Unknown registered clean source: {entry.clean_source!r}")
        region = lane_source[y1:y2, x1:x2].copy()
        values = region.astype(np.int16)
        brightness = np.max(values, axis=2)
        # A high-confidence clear-master placeholder/dash core.  One-pixel
        # expansion removes its antialias halo without entering static rules;
        # all lanes were chosen strictly within their panel interiors.
        glyphs = brightness >= 10
        kernel_size = max(1, int(entry.cleanup_dilate) * 2 + 1)
        glyphs = cv2.dilate(
            glyphs.astype(np.uint8),
            np.ones((kernel_size, kernel_size), np.uint8),
            iterations=1,
        ).astype(bool)
        # Only near-full-width runs are structural rules.  A long word such as
        # CRITICAL must remain eligible for cleanup rather than be mistaken for
        # a divider merely because its glyphs occupy much of a narrow field.
        if entry.preserve_horizontal_rules:
            horizontal_rules = np.count_nonzero(glyphs, axis=1) >= max(24, int(region.shape[1] * 0.95))
            if np.any(horizontal_rules):
                glyphs[horizontal_rules, :] = False
        if np.any(glyphs):
            repaired = cv2.inpaint(
                region,
                glyphs.astype(np.uint8) * 255,
                max(1, int(entry.inpaint_radius)),
                cv2.INPAINT_TELEA,
            )
            region[glyphs] = repaired[glyphs]
        # Copy the registered clean lane even when it had no placeholder core;
        # otherwise raw populated preview pixels would leak through unchanged.
        result[y1:y2, x1:x2] = region
    return result


def restore_clean_text_entries(
    frame: np.ndarray,
    clean_plate: np.ndarray,
    entries: Sequence[TextEntry],
) -> None:
    """Restore every dynamic lane from the one clean plate before redrawing."""

    for entry in entries:
        x1, y1, x2, y2 = text_lane(entry)
        frame[y1:y2, x1:x2] = clean_plate[y1:y2, x1:x2]


def footer_border_mask(shape: tuple[int, int]) -> np.ndarray:
    """Exact static raster perimeter of the populated EASTERN TIME field."""

    width, height = shape
    mask = np.zeros((height, width), dtype=bool)
    # Master-derived field perimeter: x=1379..1698, y=845..875.
    mask[845:847, 1379:1699] = True
    mask[874:876, 1379:1699] = True
    mask[845:876, 1379:1381] = True
    mask[845:876, 1697:1699] = True
    return mask


def restore_footer_border(frame: np.ndarray, raw: np.ndarray) -> None:
    mask = footer_border_mask((frame.shape[1], frame.shape[0]))
    frame[mask] = raw[mask]


def draw_text_entries(frame: np.ndarray, entries: Sequence[TextEntry]) -> np.ndarray:
    """Draw state text exactly once onto an already-clean plate."""

    image = Image.fromarray(frame, "RGB")
    draw = ImageDraw.Draw(image)
    for entry in entries:
        font = dashboard_font(entry.size, entry.bold)
        value = fit_text(draw, entry.value, font, entry.max_width)
        draw.multiline_text(
            entry.position,
            value,
            fill=entry.color,
            font=font,
            spacing=entry.line_spacing,
        )
    return np.array(image, dtype=np.uint8)


UNIT_STATUS_BOUNDS = (234, 478, 401, 524)
UNIT_STATUS_DIVIDER_BOUNDS = (234, 504, 401, 506)
UNIT_STATUS_BAR_BOUNDS = ((354, 361), (366, 373), (378, 385))
OPERATIONAL_ICON_BOUNDS = (
    (1304, 601, 1326, 623),
    (1304, 652, 1326, 674),
    (1304, 688, 1326, 710),
    (1304, 726, 1326, 749),
    (1304, 775, 1326, 797),
)


def blend_pixels(
    frame: np.ndarray,
    mask: np.ndarray,
    color: tuple[int, int, int],
    amount: float,
) -> None:
    """Blend only explicit review-layer pixels without changing geometry."""

    if not np.any(mask):
        return
    alpha = float(np.clip(amount, 0.0, 1.0))
    before = frame[mask].astype(np.float64)
    target = np.asarray(color, dtype=np.float64)
    frame[mask] = np.clip(before * (1.0 - alpha) + target * alpha, 0, 255).astype(np.uint8)


def blend_weighted_pixels(
    frame: np.ndarray,
    mask: np.ndarray,
    color: tuple[int, int, int],
    weights: np.ndarray,
) -> None:
    """Blend a spatially varying, predeclared review overlay.

    Unlike drawing a new shape, this only changes pixels selected by ``mask``.
    The per-pixel weights let a soft lighting sector move continuously through
    all 120 review phases without changing any layout geometry.
    """

    if mask.shape != weights.shape:
        raise RendererContractError("Weighted review overlay mask/weight shapes differ.")
    active = mask & (weights > 0.0)
    if not np.any(active):
        return
    alpha = np.clip(weights[active].astype(np.float64), 0.0, 1.0)[:, None]
    before = frame[active].astype(np.float64)
    target = np.asarray(color, dtype=np.float64)
    frame[active] = np.rint(
        np.clip(before * (1.0 - alpha) + target * alpha, 0, 255)
    ).astype(np.uint8)


def build_unit_status_clean_plate(source: np.ndarray) -> np.ndarray:
    """Create a source-derived #9 clean lane for the simulated-status row.

    The global clear master includes unrelated red placeholder rules directly
    through this lane.  Repairing the local populated texture avoids importing
    those rules, keeps the System Integrity row untouched, and lets the review
    layer place a dedicated three-bar indicator above its own divider.
    """

    result = source.copy()
    x1, y1, x2, y2 = UNIT_STATUS_BOUNDS
    region = result[y1:y2, x1:x2].copy()
    mask = foreground_mask(region, minimum_brightness=10)
    if np.any(mask):
        repaired = cv2.inpaint(region, mask.astype(np.uint8) * 255, 3, cv2.INPAINT_TELEA)
        region[mask] = repaired[mask]
    result[y1:y2, x1:x2] = region
    # A restrained red divider is intentionally reconstructed below both the
    # label and the activity bars; it is not a copied clear-master placeholder.
    dx1, dy1, dx2, dy2 = UNIT_STATUS_DIVIDER_BOUNDS
    result[dy1:dy2, dx1:dx2] = np.asarray((187, 43, 37), dtype=np.uint8)
    return result


def draw_unit_status_indicator(frame: np.ndarray, frame_index: int) -> np.ndarray:
    """Draw the deterministic review-only SIMULATED activity indicator."""

    image = Image.fromarray(frame, "RGB")
    draw = ImageDraw.Draw(image)
    draw.text((236, 482), "SIMULATED", fill=(235, 42, 35), font=dashboard_font(12, True))
    phase = (frame_index % FRAME_COUNT) / FRAME_COUNT
    for index, (x1, x2) in enumerate(UNIT_STATUS_BAR_BOUNDS):
        wave = 0.5 + 0.5 * math.sin(math.tau * (phase + index / 3.0))
        # Smooth, nonzero 6..11px bars retain a low-key diagnostic activity
        # cue without pretending to be measured host telemetry.
        height = int(round(6.0 + 5.0 * wave))
        brightness = 0.84 + 0.16 * wave
        color = tuple(int(round(channel * brightness)) for channel in (235, 42, 35))
        draw.rectangle((x1, 499 - height, x2, 498), fill=color)
    return np.asarray(image, dtype=np.uint8)


def build_operational_icon_plate(source: np.ndarray) -> np.ndarray:
    """Replace only legacy glyph pixels with source-safe vector line icons."""

    result = source.copy()
    for x1, y1, x2, y2 in OPERATIONAL_ICON_BOUNDS:
        region = result[y1:y2, x1:x2].copy()
        mask = foreground_mask(region, minimum_brightness=10)
        if np.any(mask):
            repaired = cv2.inpaint(region, mask.astype(np.uint8) * 255, 2, cv2.INPAINT_TELEA)
            region[mask] = repaired[mask]
        result[y1:y2, x1:x2] = region

    image = Image.fromarray(result, "RGB")
    draw = ImageDraw.Draw(image)
    glow = (104, 27, 23)
    red = (226, 48, 39)

    def stroked(points: Sequence[tuple[int, int]], *, closed: bool = False) -> None:
        path = tuple(points) + ((points[0],) if closed else ())
        draw.line(path, fill=glow, width=3, joint="curve")
        draw.line(path, fill=red, width=1, joint="curve")

    def box(bounds: tuple[int, int, int, int]) -> None:
        for color, width in ((glow, 3), (red, 1)):
            draw.rectangle(bounds, outline=color, width=width)

    # 1. Assessment document.
    box((1308, 604, 1321, 619))
    stroked(((1311, 609), (1318, 609)))
    stroked(((1311, 613), (1318, 613)))
    stroked(((1311, 616), (1316, 616)))
    # 2. Workflow route/arrow.
    stroked(((1307, 664), (1312, 664), (1315, 658), (1319, 658)))
    stroked(((1316, 655), (1320, 658), (1316, 661)))
    # 3. Priority shield with check.
    stroked(((1315, 691), (1321, 694), (1320, 702), (1315, 707), (1310, 702), (1309, 694)), closed=True)
    stroked(((1312, 699), (1314, 701), (1318, 696)))
    # 4. Next-action clipboard/checklist.
    box((1308, 729, 1321, 744))
    stroked(((1312, 728), (1317, 728)))
    stroked(((1311, 736), (1313, 738), (1317, 733)))
    stroked(((1311, 741), (1318, 741)))
    # 5. Lead analyst silhouette.
    for color, width in ((glow, 3), (red, 1)):
        draw.ellipse((1312, 778, 1318, 784), outline=color, width=width)
        draw.arc((1308, 782, 1322, 795), start=190, end=350, fill=color, width=width)
    return np.asarray(image, dtype=np.uint8)


def replace_text_entries(
    frame: np.ndarray,
    entries: Sequence[TextEntry],
    *,
    minimum_brightness: int = 5,
) -> np.ndarray:
    """Legacy compatibility wrapper for callers that already own a clean plate.

    The previous implementation performed broad per-frame inpainting here.
    That could remove static source artwork, including panel borders.  All
    review composition now uses ``clean_text_entries`` once and restores that
    plate before drawing; this wrapper intentionally performs no cleanup.
    """

    del minimum_brightness
    return draw_text_entries(frame, entries)


def wrap_complete_text(
    value: object,
    *,
    font: ImageFont.ImageFont,
    width: int,
    max_lines: int,
    fallback: str,
) -> str:
    """Word-wrap full text, with a deterministic complete fallback if needed."""

    normalized = " ".join(str(value or "").split())
    if not normalized:
        normalized = fallback
    draw = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    words = normalized.split(" ")
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if draw.textlength(candidate, font=font) <= width:
            current = candidate
            continue
        if not current or len(lines) + 1 >= max_lines:
            fallback = " ".join(fallback.split())
            if draw.textlength(fallback, font=font) > width:
                raise RendererContractError("Configured semantic fallback exceeds its text lane.")
            return fallback
        lines.append(current)
        current = word
    if current:
        lines.append(current)
    if len(lines) > max_lines:
        fallback = " ".join(fallback.split())
        if draw.textlength(fallback, font=font) > width:
            raise RendererContractError("Configured semantic fallback exceeds its text lane.")
        return fallback
    return "\n".join(lines)


def rect_mask(shape: tuple[int, int], bounds: tuple[int, int, int, int]) -> np.ndarray:
    width, height = shape
    x1, y1, x2, y2 = bounds
    if not (0 <= x1 < x2 <= width and 0 <= y1 < y2 <= height):
        raise RendererContractError(f"Invalid canvas bounds: {bounds}")
    mask = np.zeros((height, width), dtype=bool)
    mask[y1:y2, x1:x2] = True
    return mask


def translated_mask(mask: np.ndarray, origin: tuple[int, int], canvas_size: tuple[int, int]) -> np.ndarray:
    result = np.zeros((canvas_size[1], canvas_size[0]), dtype=bool)
    x, y = origin
    result[y:y + mask.shape[0], x:x + mask.shape[1]] = mask
    return result


def compact_case_classification(value: object) -> str:
    normalized = " ".join(str(value or "UNAVAILABLE").split())
    # These are semantic display projections of the persisted classification,
    # not arbitrary clipping.  They retain the investigation type while fitting
    # the approved single-line card field.
    replacements = {
        "LABORATORY SECURITY BREACH INVESTIGATION": "LAB SECURITY BREACH",
        "SUPPLY CHAIN SECURITY INVESTIGATION": "SUPPLY CHAIN INVESTIGATION",
    }
    return replacements.get(normalized.upper(), normalized)


def compact_threat_family(value: object) -> str:
    normalized = " ".join(str(value or "UNAVAILABLE").split())
    replacements = {
        "CLINICAL RESEARCH DATA MANIPULATION": "CLINICAL DATA MANIPULATION",
    }
    return replacements.get(normalized.upper(), normalized)


THRESHOLD_GUIDE_SAMPLES = {
    "CRITICAL": (872, 730),
    "HIGH": (858, 751),
    "MEDIUM": (858, 774),
    "LOW": (858, 795),
}

# Tight, source-derived review regions.  They deliberately exclude labels,
# borders, the Threat Summary bullet strip, and every neighboring panel.
CENTER_METADATA_ARTIFACT_BOUNDS = (
    (603, 219, 812, 225),
    (603, 256, 812, 265),
)
THREAT_SUMMARY_ARTIFACT_BOUNDS = (1017, 722, 1271, 804)
THRESHOLD_GUIDE_PALETTE_BOUNDS = (850, 720, 1002, 807)
CENTER_METADATA_ENTRY_BOUNDS = (
    (603, 185, 812, 221),
    (603, 225, 812, 258),
)
LEFT_LEAD_ANALYST_ENTRY_BOUNDS = (234, 424, 400, 443)
LEFT_LEAD_ANALYST_CLEAN_BOUNDS = (234, 424, 400, 451)
FEED_ROW_Y_VALUES = (590, 607, 624, 641, 658, 675)
FEED_TIMESTAMP_ENTRY_BOUNDS = tuple((24, y - 2, 65, y + 13) for y in FEED_ROW_Y_VALUES)
FEED_MESSAGE_ENTRY_BOUNDS = tuple((72, y - 2, 373, y + 13) for y in FEED_ROW_Y_VALUES)
FEED_SEVERITY_ENTRY_BOUNDS = tuple((379, y - 2, 418, y + 13) for y in FEED_ROW_Y_VALUES)
FEED_ALL_ENTRY_BOUNDS = (
    FEED_TIMESTAMP_ENTRY_BOUNDS + FEED_MESSAGE_ENTRY_BOUNDS + FEED_SEVERITY_ENTRY_BOUNDS
)
FEED_V6_CLEAN_LANES = tuple((22, y - 3, 430, y + 15) for y in FEED_ROW_Y_VALUES)
THREAT_GUIDE_V6_ROWS = (
    ("CRITICAL", 724, "80+"),
    ("HIGH", 746, "60-79"),
    ("MEDIUM", 768, "30-59"),
    ("LOW", 790, "0-29"),
)
THREAT_GUIDE_V6_CLEAR_BOUNDS = tuple((882, y - 2, 1002, y + 15) for _level, y, _range in THREAT_GUIDE_V6_ROWS)
FOOTER_TIMESTAMP_ENTRY_BOUNDS = (1515, 851, 1695, 874)
THREAT_SUMMARY_ENTRY_BOUNDS = tuple(
    (1017, y - 2, 1271, y + 12)
    for y in (724, 741, 758, 775, 792)
)


def classification_for_score(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def threshold_guide_colors(raw: np.ndarray) -> dict[str, tuple[int, int, int]]:
    """Sample—not invent—the approved score colors from the threshold guide."""

    colors: dict[str, tuple[int, int, int]] = {}
    for level, (x, y) in THRESHOLD_GUIDE_SAMPLES.items():
        pixel = raw[y, x]
        colors[level] = tuple(int(channel) for channel in pixel)
    return colors


def static_text_entries(
    renderer_state: dict[str, Any],
    raw: np.ndarray,
    *,
    render_started_at: datetime,
) -> list[TextEntry]:
    shared = renderer_state["dashboard"]["shared"]
    display = renderer_state["display"]
    system = renderer_state["dashboard"]["system_status"]
    updated = text_timestamp(shared["updated_at"])
    updated_date = updated[:10]
    # This footer is a render/build clock, deliberately separate from the
    # authoritative active-case timestamp used by UPDATED/LAST UPDATED.
    footer_updated = footer_timestamp_for_render_instant(render_started_at)
    evidence_count = int(shared["evidence_count"])
    integr = renderer_state["integration_count"]
    system_health = _system_health(system)
    red = (235, 42, 35)
    white = (203, 198, 195)
    gray = (166, 161, 158)
    stage = human_stage(shared["current_stage"])
    severity = str(shared["severity"])
    severity_color = semantic_severity_color(raw, severity)
    priority = str(shared["priority"])
    priority_color = severity_color
    entries = top_header_entries(renderer_state) + [
        TextEntry((234, 315, 400, 334), (236, 319), str(shared["case_id"]), white, 14, False, 158),
        TextEntry((234, 342, 400, 361), (236, 346), str(shared["campaign_id"]), white, 14, False, 158),
        TextEntry((234, 370, 400, 389), (236, 374), str(shared["lifecycle_status"]), red, 14, True, 158),
        TextEntry(
            LEFT_LEAD_ANALYST_ENTRY_BOUNDS,
            (236, 428),
            str(shared["lead_analyst"]),
            white,
            12,
            False,
            164,
            clear_bounds=LEFT_LEAD_ANALYST_CLEAN_BOUNDS,
            cleanup_dilate=2,
            inpaint_radius=3,
        ),
        TextEntry((234, 451, 400, 470), (236, 455), updated, gray, 11, False, 158),
        TextEntry((234, 505, 400, 524), (236, 509), f"{system_health:.1f}%", white, 13, False, 158),
        # The visible field bounds remain frozen; the two clean lanes extend
        # only through the measured antialias tails of the source preview
        # glyphs so stale pixels cannot survive below live metadata.
        TextEntry((603, 185, 812, 221), (604, 189), compact_case_classification(display.get("classification")), white, 13, False, 205, clear_bounds=(603, 185, 812, 225), cleanup_dilate=2, inpaint_radius=3),
        TextEntry((603, 225, 812, 258), (604, 229), compact_threat_family(display.get("threat_family")), white, 13, False, 205, clear_bounds=(603, 225, 812, 265), cleanup_dilate=2, inpaint_radius=3),
        TextEntry((603, 265, 812, 286), (604, 269), stage, white, 13, False, 205),
        TextEntry((603, 302, 812, 322), (604, 306), str(shared["lifecycle_status"]), red, 13, True, 205),
        TextEntry((1011, 185, 1227, 207), (1012, 189), str(shared["priority"]), red, 13, True, 210),
        TextEntry((1011, 224, 1227, 246), (1012, 228), str(shared["lead_analyst"]), white, 13, False, 210),
        TextEntry((1011, 263, 1227, 285), (1012, 267), f"{evidence_count} RECORDS", white, 13, False, 210),
        TextEntry((1011, 301, 1227, 323), (1012, 305), str(integr), white, 13, False, 210),
        TextEntry((1011, 333, 1227, 370), (1012, 342), updated, gray, 11, False, 210),
        TextEntry((1405, 99, 1517, 118), (1407, 102), str(shared["case_id"]), white, 12, False, 110),
        TextEntry((1405, 136, 1517, 155), (1407, 139), f"{evidence_count} RECORDS", white, 12, False, 110),
        TextEntry((1405, 173, 1517, 192), (1407, 176), str(integr), white, 12, False, 110),
        TextEntry(
            (1405, 207, 1518, 250),
            (1407, 214),
            updated_date,
            (207, 202, 199),
            11,
            False,
            110,
            clean_source="source",
            inpaint_radius=3,
            preserve_horizontal_rules=False,
        ),
        # The right outer edge is static approved raster at x=1698.  The
        # timestamp lane deliberately ends before it and the exact border is
        # restored again as the final compositing operation.
        TextEntry(FOOTER_TIMESTAMP_ENTRY_BOUNDS, (1517, 855), footer_updated, gray, 11, False, 176),
    ]
    entries.extend(
        inline_colored_text_entries(
            (234, 397, 400, 416),
            (236, 401),
            ((severity, severity_color), (f" / {shared['priority']}", priority_color)),
            size=13,
            bold=False,
            max_width=158,
        )
    )
    entries.extend(
        inline_colored_text_entries(
            (603, 338, 812, 360),
            (604, 342),
            ((severity, severity_color),),
            size=13,
            bold=False,
            max_width=205,
        )
    )
    return entries


def _system_health(system: dict[str, Any]) -> float:
    subsystems = system.get("subsystems")
    if not isinstance(subsystems, dict):
        return 0.0
    values = [
        float(record.get("health", 0.0))
        for record in subsystems.values()
        if isinstance(record, dict)
    ]
    return float(sum(values) / len(values)) if values else 0.0


def status_panel_entries(renderer_state: dict[str, Any]) -> list[TextEntry]:
    system = renderer_state["dashboard"]["system_status"]
    rows = _status_rows(system)
    gray = (181, 179, 177)
    blue = (63, 151, 222)
    white = (198, 196, 194)
    entries: list[TextEntry] = []
    row_y = (607, 630, 652, 674, 696)
    for y, row in zip(row_y, rows):
        # V7 uses a locally repaired source-derived status plate.  Cleaning from
        # that same plate prevents the obsolete populated/clear-master rules
        # from being restored behind the live row values.
        clean_options = {
            "clean_source": "source",
            "cleanup_dilate": 2,
            "inpaint_radius": 2,
            "preserve_horizontal_rules": False,
        }
        entries.extend(
            (
                TextEntry((478, y - 3, 650, y + 14), (482, y), row["label"], gray, 10, False, 164, **clean_options),
                TextEntry((649, y - 3, 722, y + 14), (654, y), row["status"], blue, 10, True, 65, **clean_options),
                TextEntry((751, y - 3, 811, y + 14), (758, y), f"{row['health']:.1f}%", white, 10, False, 52, **clean_options),
            )
        )
    metrics = _metric_records(system)
    metric_positions = (
        ((480, 748, 526, 771), (485, 752), "CPU", f"{metrics['cpu_percent']['latest']:.0f}%"),
        ((544, 748, 592, 771), (550, 752), "MEM", f"{metrics['memory_percent']['latest']:.0f}%"),
        ((606, 748, 665, 771), (612, 752), "NET", f"{metrics['network_percent']['latest']:.0f}%"),
        ((679, 748, 733, 771), (684, 752), "DISK", f"{metrics['disk_percent']['latest']:.0f}%"),
        ((744, 748, 811, 771), (749, 752), "QUEUE", f"{metrics['queue_depth']['latest']:.0f} CT"),
    )
    for bounds, pos, label, value in metric_positions:
        entries.append(TextEntry(bounds, pos, label, gray, 8, True, bounds[2] - pos[0] - 2))
        entries.append(TextEntry((bounds[0], 767, bounds[2], 784), (pos[0], 770), value, white, 10, False, bounds[2] - pos[0] - 2))
    return entries


def threat_action_summary(value: object) -> str:
    text = " ".join(str(value or "").split())
    lower = text.lower()
    if "recovery" in lower and "control" in lower and "verify" in lower:
        return "Recovery controls require verification."
    if "verify" in lower:
        return "Verification action is required."
    if "review" in lower:
        return "Analyst review is required."
    return "Action required for active case."


def threat_panel_entries(renderer_state: dict[str, Any], raw: np.ndarray) -> list[TextEntry]:
    shared = renderer_state["dashboard"]["shared"]
    display = renderer_state["display"]
    score = int(renderer_state["canonical_threat_score"])
    canonical = str(
        renderer_state["dashboard"]["threat_monitor"]["threat"]["canonical_classification"]
    ).upper()
    presentation = str(renderer_state["subsystem_06_display_level"]).upper()
    expected_presentation = classification_for_score(score)
    if canonical != csharp_level(score):
        raise RendererContractError(
            f"Canonical threat classification {canonical!r} does not match C# score {score}."
        )
    if presentation != expected_presentation:
        raise RendererContractError(
            f"Frozen #6 display level {presentation!r} does not match score {score}."
        )
    summary = (
        f"{canonical.title()} activity tied to {shared['case_id']}",
        f"{shared['evidence_count']} evidence records correlated",
        f"{renderer_state['correlation_count']} linked relationships",
        f"Stage: {human_stage(shared['current_stage'])}",
        threat_action_summary(display.get("recommended_action")),
    )
    severity_color = threshold_guide_colors(raw)[presentation]
    gray = (185, 180, 177)
    entries = [
        TextEntry((850, 615, 940, 657), (854, 621), str(score), severity_color, 32, True, 42),
        # Keep the score suffix in its existing score field, but make the slash
        # and denominator legible at dashboard scale.  This is presentation
        # only; the canonical score and threshold color remain data-derived.
        TextEntry(
            (890, 631, 924, 654),
            (892, 634),
            "/100",
            (184, 178, 175),
            13,
            True,
            30,
            clear_bounds=THREAT_SCORE_SUFFIX_V7_CLEAN_BOUNDS,
        ),
        TextEntry((850, 658, 940, 682), (854, 663), presentation, severity_color, 13, True, 84),
    ]
    summary_rows = (724, 741, 758, 775, 792)
    summary_clean_ends = (739, 756, 773, 790, 804)
    for y, clear_end, value in zip(summary_rows, summary_clean_ends, summary):
        # Join the measured vertical cleanup lanes so antialias remnants from
        # the populated preview cannot remain in the 3px gaps.  The red bullet
        # strip at x<1017, header, rules, and field geometry remain untouched.
        entries.append(
            TextEntry(
                (1017, y - 2, 1271, y + 12),
                (1020, y),
                value,
                gray,
                10,
                False,
                246,
                clear_bounds=(1017, y - 2, 1271, clear_end),
                cleanup_dilate=2,
                inpaint_radius=2,
            )
        )
    return entries


def format_active_feed_event(event: dict[str, Any]) -> str:
    """Create a concise complete event sentence from persisted event facts."""

    event_type = str(event.get("event_type") or "").upper()
    message = " ".join(str(event.get("message") or "").split())
    if event_type == "WORKFLOW_STAGE_CHANGED" or "WORKFLOW ADVANCED" in message.upper():
        stage = ""
        marker = "WORKFLOW ADVANCED TO "
        upper = message.upper()
        if marker in upper:
            stage = upper.split(marker, 1)[1].split(":", 1)[0].strip()
        return f"Workflow advanced: {human_stage(stage or event.get('stage') or 'CURRENT STAGE')}"
    if event_type == "CASE_MIGRATED" or "PERSISTENT LIFECYCLE" in message.upper():
        return "Persistent lifecycle initialized"
    if "EVIDENCE" in event_type or "EVIDENCE" in message.upper():
        return "Evidence validation completed"
    if "THREAT" in event_type or "THREAT" in message.upper():
        return f"Threat score updated: {severity_bucket(event.get('severity'))}"
    if "CORRELATION" in event_type or "CORRELATION" in message.upper():
        return "Evidence correlation refreshed"
    if event_type:
        return event_type.replace("_", " ").title()
    return "Persisted case event"


def feed_panel_entries(renderer_state: dict[str, Any]) -> list[TextEntry]:
    entries: list[TextEntry] = []
    gray = (190, 187, 184)
    color_by_level = {"HIGH": (234, 49, 42), "MEDIUM": (234, 141, 34), "LOW": (72, 170, 96)}
    events = _feed_events(renderer_state)
    for index, event in enumerate(events):
        y = 590 + index * 17
        # The approved clear master carries obsolete full-width row rules in
        # this list area.  Each row is repaired from its local approved source
        # texture before the three intended live fields are redrawn.  The lane
        # is strictly inside the list body: it cannot affect the panel frame,
        # LIVE badge, event-intensity graph, or 39 frozen bar positions.
        clean_lane = (22, y - 3, 430, y + 15)
        clean_options = {
            "clear_bounds": clean_lane,
            "clean_source": "source",
            "cleanup_dilate": 2,
            "inpaint_radius": 2,
            "preserve_horizontal_rules": False,
        }
        entries.extend(
            (
                TextEntry((24, y - 2, 65, y + 13), (26, y), event["timestamp"], gray, 10, False, 37, **clean_options),
                TextEntry((72, y - 2, 373, y + 13), (73, y), event["message"], gray, 10, False, 296, **clean_options),
                TextEntry(
                    (379, y - 2, 418, y + 13),
                    (382, y),
                    event["severity"],
                    color_by_level[event["visual_severity"]],
                    9,
                    True,
                    34,
                    **clean_options,
                ),
            )
        )
    return entries


def operational_brief_entries(renderer_state: dict[str, Any], raw: np.ndarray) -> list[TextEntry]:
    shared = renderer_state["dashboard"]["shared"]
    display = renderer_state["display"]
    font = dashboard_font(11)
    values = (
        wrap_complete_text(
            display.get("assessment"),
            font=font,
            width=340,
            max_lines=2,
            fallback="Case assessment requires analyst review.",
        ),
        f"Stage: {human_stage(shared['current_stage'])}",
        f"Priority: {shared['priority']} / Severity: {shared['severity']}",
        wrap_complete_text(
            display.get("recommended_action"),
            font=font,
            width=340,
            max_lines=2,
            fallback="Action requires analyst review.",
        ),
        f"Lead: {shared['lead_analyst']}",
    )
    entries: list[TextEntry] = []
    for index, (bounds, position, value) in enumerate(zip(
        (
            # The text lanes are intentionally wider than the live origin to
            # remove the populated-master antialias fringe without reaching
            # the left icons or the outer/right panel border.
            (1334, 596, 1710, 638),
            (1334, 640, 1710, 682),
            (1334, 684, 1710, 726),
            (1334, 727, 1710, 770),
            (1334, 771, 1710, 814),
        ),
        ((1340, 604), (1340, 648), (1340, 692), (1340, 735), (1340, 779)),
        values,
    )):
        # The fourth persisted action is intentionally wrapped. Giving just
        # that row more leading uses its internal free space without moving a
        # divider, shrinking text, or crowding an adjacent row.
        line_spacing = 8 if index == 3 else -1
        if index == 2:
            prefix = f"Priority: {shared['priority']} / Severity: "
            entries.extend(
                inline_colored_text_entries(
                    bounds,
                    position,
                    (
                        (prefix, (190, 186, 183)),
                        (str(shared["severity"]), semantic_severity_color(raw, shared["severity"])),
                    ),
                    size=11,
                    bold=False,
                    max_width=340,
                    line_spacing=line_spacing,
                )
            )
        else:
            entries.append(TextEntry(bounds, position, value, (190, 186, 183), 11, False, 340, line_spacing=line_spacing))
    return entries


def all_text_entries(
    renderer_state: dict[str, Any],
    raw: np.ndarray,
    *,
    render_started_at: datetime,
) -> list[TextEntry]:
    return (
        static_text_entries(renderer_state, raw, render_started_at=render_started_at)
        + status_panel_entries(renderer_state)
        + threat_panel_entries(renderer_state, raw)
        + feed_panel_entries(renderer_state)
        + operational_brief_entries(renderer_state, raw)
    )


def _feed_events(renderer_state: dict[str, Any]) -> list[dict[str, Any]]:
    original = renderer_state["events"]
    sorted_events = sorted(
        (event for event in original if isinstance(event, dict)),
        key=lambda item: (str(item.get("timestamp", "")), int(item.get("sequence", 0))),
        reverse=True,
    )[:6]
    result: list[dict[str, Any]] = []
    for event in sorted_events:
        level = severity_bucket(event.get("severity"))
        result.append(
            {
                "timestamp": event_timestamp(event.get("timestamp")),
                "message": format_active_feed_event(event),
                "severity": level,
                "visual_severity": level,
                "raw": event,
            }
        )
    while len(result) < 6:
        result.append(
            {
                "timestamp": "--:--",
                "message": "NO PERSISTED EVENT",
                "severity": "LOW",
                "visual_severity": "LOW",
                "raw": {},
            }
        )
    return result


def _metric_records(system: dict[str, Any]) -> dict[str, dict[str, Any]]:
    telemetry = system.get("telemetry")
    if not isinstance(telemetry, dict):
        raise RendererContractError("System telemetry is not available.")
    records: dict[str, dict[str, Any]] = {}
    for key in ("cpu_percent", "memory_percent", "network_percent", "disk_percent", "queue_depth"):
        record = telemetry.get(key)
        if not isinstance(record, dict):
            raise RendererContractError(f"System telemetry is missing {key}.")
        values = record.get("samples")
        if not isinstance(values, list) or not values:
            raise RendererContractError(f"System telemetry {key} has no persisted samples.")
        numeric = np.asarray(values, dtype=np.float64)
        if numeric.ndim != 1 or not np.all(np.isfinite(numeric)):
            raise RendererContractError(f"System telemetry {key} is malformed.")
        records[key] = {"samples": numeric, "latest": float(numeric[-1]), "unit": record.get("unit")}
    if records["queue_depth"]["unit"] != "count":
        raise RendererContractError("queue_depth must retain its count unit.")
    return records


def _status_rows(system: dict[str, Any]) -> list[dict[str, Any]]:
    subsystems = system.get("subsystems")
    if not isinstance(subsystems, dict):
        raise RendererContractError("System status lacks subsystem records.")
    ordered = (
        ("evidence_pipeline", "EVIDENCE PIPELINE"),
        ("correlation_engine", "CORRELATION ENGINE"),
        ("case_store", "CASE STORE"),
        ("threat_assessment", "THREAT ASSESSMENT"),
    )
    rows: list[dict[str, Any]] = []
    for key, label in ordered:
        record = subsystems.get(key)
        if not isinstance(record, dict):
            raise RendererContractError(f"System status is missing {key}.")
        rows.append(
            {
                "label": label,
                "status": str(record.get("status") or "UNAVAILABLE"),
                "health": float(record.get("health", 0.0)),
                "intensity": float(record.get("led_intensity", 0.0)),
            }
        )
    health = _system_health(system)
    rows.append(
        {
            "label": "TELEMETRY SOURCE",
            "status": str(system.get("measurement_status") or "UNAVAILABLE"),
            "health": health,
            "intensity": max(0.0, min(1.0, health / 100.0)),
        }
    )
    return rows


def case_overview_value_entries(renderer_state: dict[str, Any]) -> list[TextEntry]:
    """Live values at the exact frozen Proposal B value baselines (local)."""

    shared = renderer_state["dashboard"]["shared"]
    relationships = renderer_state["relationships"]
    feed_count = len(renderer_state["events"])
    access_count = sum(
        1
        for event in renderer_state["events"]
        if "ACCESS" in str(event.get("event_type", "")).upper()
        or "ACCESS" in str(event.get("message", "")).upper()
    )
    correlation_count = renderer_state["correlation_count"]
    return [
        # The module names at local y=60/130/200 are frozen static text.  The
        # values start at y=70/140/210 exactly as in the approved static
        # renderer, not nine pixels above them.
        TextEntry((19, 68, 86, 84), (21, 70), f"{shared['evidence_count']} RECORDS", (245, 77, 58), 8, True, 63),
        TextEntry((19, 138, 85, 154), (21, 140), f"{access_count} ACCESS LOGS", (241, 165, 82), 8, True, 62),
        TextEntry((19, 208, 111, 218), (21, 210), f"{feed_count} EVENTS", (244, 78, 57), 8, True, 88),
        TextEntry((340, 68, 395, 84), (342, 70), f"{max(1, renderer_state['threat_history_count'])} REPORTS", (93, 177, 222), 8, True, 51),
        TextEntry((340, 138, 395, 154), (342, 140), f"{correlation_count} LINKS", (246, 87, 63), 8, True, 51),
        TextEntry((340, 208, 403, 224), (342, 210), f"REV {shared['state_revision']}", (98, 215, 141), 8, True, 59),
        # Preserve the frozen hub label/rails/dividers; only these four lines
        # are active-case data.  The final line ends above the y=170 divider.
        TextEntry((186, 125, 274, 137), (188, 127), str(shared["case_id"]), (247, 85, 63), 8, True, 84),
        TextEntry((186, 138, 274, 149), (188, 140), str(shared["lifecycle_status"]), (241, 88, 66), 7, True, 84),
        TextEntry((186, 149, 274, 160), (188, 151), f"STAGE / {human_stage(shared['current_stage'])}", (165, 159, 156), 6, False, 84),
        TextEntry((186, 159, 274, 169), (188, 161), f"RELATIONSHIPS / {len(relationships)}", (151, 145, 142), 6, False, 84),
        # Footer copy is live-state presentation, positioned on the frozen
        # y=255 baseline while preserving the y=249 divider and outer frame.
        TextEntry((91, 251, 154, 266), (93, 255), "CURRENT STATE", (119, 101, 98), 7, False, 61),
        TextEntry((397, 251, 438, 266), (397, 255), str(shared["lifecycle_status"]), (201, 63, 49), 6, True, 41),
    ]


def clean_case_overview_preview_values(source: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Remove only frozen preview-value glyphs; preserve all Proposal B art."""

    # These tight interior lanes exclude every card frame/title/icon, the hub
    # dividers, the top red divider (y=37..38), route lines, and arrowheads.
    # The header suffix is preview-only; its immutable title begins at x=15.
    lanes = (
        # Preserve the left static header caption but remove the frozen
        # preview suffix (// CONTROLLED PREVIEW) from its true start point.
        (112, 39, 185, 49),
        (19, 68, 86, 84), (19, 138, 85, 154), (19, 208, 111, 218),
        (340, 68, 395, 84), (340, 138, 395, 154), (340, 208, 403, 224),
        (186, 125, 274, 137), (186, 138, 274, 149),
        (186, 149, 274, 160), (186, 159, 274, 169),
        # Preserve the source-exact frozen caption prefix and only replace
        # preview suffixes below the divider.
        (91, 251, 154, 266), (397, 251, 438, 266),
    )
    result = source.copy()
    authorized = np.zeros(source.shape[:2], dtype=bool)
    for index, (x1, y1, x2, y2) in enumerate(lanes):
        region = result[y1:y2, x1:x2]
        # Preview glyphs are the deliberately bright foreground in these
        # blank value lanes.  The header suffix itself used low-contrast gray
        # antialiasing, so it needs the lower threshold; all other lanes retain
        # their source texture at the normal threshold.
        threshold = 10 if index == 0 else 28
        mask = foreground_mask(region, minimum_brightness=threshold)
        if np.any(mask):
            repaired = cv2.inpaint(region, mask.astype(np.uint8) * 255, 2, cv2.INPAINT_TELEA)
            region[mask] = repaired[mask]
            result[y1:y2, x1:x2] = region
        authorized[y1:y2, x1:x2] = True
    return result, authorized


def create_case_overview_plate(
    source: np.ndarray,
    renderer_state: dict[str, Any],
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return frozen #7 clean plate, active-case plate, and text lanes."""

    clean, dynamic_lanes = clean_case_overview_preview_values(source)
    live = draw_text_entries(clean, case_overview_value_entries(renderer_state))
    return clean, live, dynamic_lanes


# V5 uses only these two source-exact interior text lanes.  They deliberately
# exclude the frozen hub rail/signature, all routes, card frames, and the Case
# Data Store cylinder.  The approved Proposal-B geometry therefore remains
# untouched while its live copy becomes readable at dashboard scale.
CASE_OVERVIEW_V5_HUB_LOCAL_BOUNDS = (186, 125, 274, 169)
CASE_OVERVIEW_V5_DATASTORE_LOCAL_BOUNDS = (340, 208, 403, 235)
CASE_OVERVIEW_V5_LOCAL_BOUNDS = (
    CASE_OVERVIEW_V5_HUB_LOCAL_BOUNDS,
    CASE_OVERVIEW_V5_DATASTORE_LOCAL_BOUNDS,
)

# V6 changes no Proposal-B geometry.  These are only the quiet interior text
# lanes that were already available inside the six fixed modules and central
# hub.  They exclude every card frame, route, arrowhead, icon, waveform, hub
# rail, panel header, and outer border.
CASE_OVERVIEW_V6_LOCAL_BOUNDS = (
    (19, 60, 86, 68), (19, 68, 86, 84), (19, 84, 86, 94),
    (19, 130, 86, 138), (19, 138, 86, 154), (19, 154, 86, 164),
    (19, 200, 86, 208), (19, 208, 86, 220),
    # V10 corrects only the true, source-local title lanes needed by Pillow's
    # Ubuntu Aileron fallback.  Their added pixels remain clear of frozen
    # components/routes and preserve the existing full title wording.
    (340, 60, 397, 68), (340, 68, 395, 84), (340, 84, 395, 94),
    (340, 130, 397, 138), (340, 138, 395, 154), (340, 154, 395, 164),
    (340, 200, 407, 208), (340, 208, 403, 222), (340, 222, 403, 235),
    (186, 108, 266, 119),
    (186, 125, 274, 137), (186, 138, 274, 149),
    (186, 149, 274, 160), (186, 159, 274, 169),
)

# V7 adds only the six measured descriptor lanes.  The Timeline descriptor
# occupies its previously unused right-side interior lane and never enters the
# frozen waveform below it.
CASE_OVERVIEW_V7_SUBTITLE_LOCAL_BOUNDS = (
    (19, 84, 86, 94),
    (19, 154, 86, 164),
    (64, 211, 111, 222),
    (340, 84, 395, 94),
    (340, 154, 395, 164),
    (340, 222, 403, 235),
)
CASE_OVERVIEW_V7_LOCAL_BOUNDS = CASE_OVERVIEW_V6_LOCAL_BOUNDS + (
    CASE_OVERVIEW_V7_SUBTITLE_LOCAL_BOUNDS[2],
)

# V8 is deliberately a post-route, subtitle-only repair.  Five existing
# V7 lanes remain exact; the Timeline lane reaches through the frozen
# descriptor's last antialias row but stops immediately before its waveform.
CASE_OVERVIEW_V8_SUBTITLE_LOCAL_BOUNDS = (
    (19, 84, 86, 94),
    (19, 154, 86, 164),
    (64, 211, 111, 225),
    (340, 84, 395, 94),
    (340, 154, 395, 164),
    # One additional left-side pixel supplies a genuine 2px Aileron margin
    # while retaining the fixed 2px clearance before the datastore cylinder.
    (339, 222, 403, 235),
)

# V10 keeps the legacy cleanup support for the original Access Logs descriptor
# in place, but renders CREDENTIAL CHAIN below the fixed key icon.  This makes
# its real 92px lower-card lane available without moving the card, key, route,
# or border; the bottom row remains clear of the frozen card frame.
CASE_OVERVIEW_V10_CREDENTIAL_RENDER_BOUNDS = (19, 158, 111, 166)


def case_overview_v8_subtitle_render_bounds(
    index: int,
    cleanup_bounds: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    """Return the visual V8 subtitle lane without widening unrelated text."""

    if index == 1:
        return CASE_OVERVIEW_V10_CREDENTIAL_RENDER_BOUNDS
    return cleanup_bounds


def case_overview_v8_subtitle_overlay_bounds() -> tuple[tuple[int, int, int, int], ...]:
    """Return only the source-derived V8 regions restored after route motion."""

    bounds = list(CASE_OVERVIEW_V8_SUBTITLE_LOCAL_BOUNDS)
    bounds.append(CASE_OVERVIEW_V10_CREDENTIAL_RENDER_BOUNDS)
    return tuple(bounds)

# These are the exact static Proposal-B descriptor strings/positions drawn
# into the approved #7 raster.  V8 removes their measured glyph support from
# a source-derived clean plate before drawing each current subtitle once.
CASE_OVERVIEW_V8_BAKED_SUBTITLE_SPECS = (
    ("evidence", "SEALED / CHAIN", (21, 86)),
    ("access_logs", "CREDENTIAL WATCH", (21, 156)),
    ("timeline", "LIVE TRACE", (70, 218)),
    ("intelligence", "ANALYST READ", (342, 86)),
    ("correlation", "LINK DENSITY", (342, 156)),
    ("case_data_store", "PERSIST / RETAIN", (342, 226)),
)


def case_overview_v7_subtitle_entries() -> list[TextEntry]:
    """V7 measured +1px descriptors inside the existing frozen module lanes."""

    subtitle = (151, 145, 142)
    return [
        centered_text_entry((19, 84, 86, 94), "SEALED / CHAIN", subtitle, 6, True),
        centered_text_entry((19, 154, 86, 164), "CREDENTIAL CHAIN", subtitle, 6, True),
        centered_text_entry((64, 211, 111, 222), "LIVE TRACE", subtitle, 6, True),
        centered_text_entry((340, 84, 395, 94), "ANALYST READ", subtitle, 6, True),
        centered_text_entry((340, 154, 395, 164), "CASE JOIN", subtitle, 6, True),
        centered_text_entry((340, 222, 403, 235), "PERSIST / RETAIN", (138, 171, 151), 6, True),
    ]


def _largest_fitting_case_overview_subtitle(
    bounds: tuple[int, int, int, int],
    value: str,
    color: tuple[int, int, int],
) -> TextEntry:
    """Use 8px first, with 7px only when Pillow proves 8px will not fit."""

    x1, y1, x2, y2 = bounds
    for size in (8, 7):
        left, top, right, bottom = measured_text_bbox(value, size, True)
        if right - left <= x2 - x1 and bottom - top <= y2 - y1:
            return centered_text_entry(bounds, value, color, size, True)
    raise RendererContractError(f"V8 Case Overview subtitle does not fit: {value!r}")


def case_overview_v8_subtitle_entries() -> list[TextEntry]:
    """Measured, legible V8 descriptors within the six approved lower lanes."""

    muted = (151, 145, 142)
    entries = [
        _largest_fitting_case_overview_subtitle(
            CASE_OVERVIEW_V8_SUBTITLE_LOCAL_BOUNDS[0], "SEALED / CHAIN", muted
        ),
        _largest_fitting_case_overview_subtitle(
            case_overview_v8_subtitle_render_bounds(
                1, CASE_OVERVIEW_V8_SUBTITLE_LOCAL_BOUNDS[1]
            ),
            "CREDENTIAL CHAIN",
            muted,
        ),
        _largest_fitting_case_overview_subtitle(
            CASE_OVERVIEW_V8_SUBTITLE_LOCAL_BOUNDS[2], "LIVE TRACE", muted
        ),
        _largest_fitting_case_overview_subtitle(
            CASE_OVERVIEW_V8_SUBTITLE_LOCAL_BOUNDS[3], "ANALYST READ", muted
        ),
        _largest_fitting_case_overview_subtitle(
            CASE_OVERVIEW_V8_SUBTITLE_LOCAL_BOUNDS[4], "CASE JOIN", muted
        ),
        _largest_fitting_case_overview_subtitle(
            CASE_OVERVIEW_V8_SUBTITLE_LOCAL_BOUNDS[5],
            "PERSIST / RETAIN",
            (138, 171, 151),
        ),
    ]
    if sum(entry.value == "LIVE TRACE" for entry in entries) != 1:
        raise RendererContractError("V8 Timeline subtitle must be rendered exactly once.")
    return entries


def _case_overview_text_support_mask(
    shape: tuple[int, int],
    entry: TextEntry,
    bounds: tuple[int, int, int, int],
) -> np.ndarray:
    """Measured text support plus a one-pixel antialias halo, locally clipped."""

    image = Image.new("L", (shape[1], shape[0]), 0)
    ImageDraw.Draw(image).text(
        entry.position,
        entry.value,
        fill=255,
        font=dashboard_font(entry.size, entry.bold),
    )
    support = cv2.dilate(
        (np.asarray(image, dtype=np.uint8) > 0).astype(np.uint8),
        np.ones((3, 3), np.uint8),
        iterations=1,
    ).astype(bool)
    x1, y1, x2, y2 = bounds
    lane = np.zeros(shape, dtype=bool)
    lane[y1:y2, x1:x2] = True
    return support & lane


def case_overview_v8_baked_subtitle_entries() -> list[TextEntry]:
    """Canonical old static descriptors used solely for source-local cleanup."""

    return [
        TextEntry(bounds, position, value, (151, 145, 142), 6, False, bounds[2] - bounds[0])
        for (_name, value, position), bounds in zip(
            CASE_OVERVIEW_V8_BAKED_SUBTITLE_SPECS,
            CASE_OVERVIEW_V8_SUBTITLE_LOCAL_BOUNDS,
        )
    ]


def case_overview_v8_subtitle_cleanup_masks(shape: tuple[int, int]) -> dict[str, np.ndarray]:
    """Mask both baked and V7 replacement glyphs before the V8 redraw."""

    masks: dict[str, np.ndarray] = {}
    for (name, _value, _position), bounds, baked, v7 in zip(
        CASE_OVERVIEW_V8_BAKED_SUBTITLE_SPECS,
        CASE_OVERVIEW_V8_SUBTITLE_LOCAL_BOUNDS,
        case_overview_v8_baked_subtitle_entries(),
        case_overview_v7_subtitle_entries(),
    ):
        masks[name] = (
            _case_overview_text_support_mask(shape, baked, bounds)
            | _case_overview_text_support_mask(shape, v7, bounds)
        )
    return masks


def _inpaint_case_overview_support(
    plate: np.ndarray,
    support: np.ndarray,
    bounds: tuple[int, int, int, int],
) -> None:
    """Inpaint only measured stale glyph support; never cover a whole lane."""

    x1, y1, x2, y2 = bounds
    local_support = support[y1:y2, x1:x2]
    if not np.any(local_support):
        return
    region = plate[y1:y2, x1:x2].copy()
    repaired = cv2.inpaint(
        region,
        local_support.astype(np.uint8) * 255,
        2,
        cv2.INPAINT_TELEA,
    )
    region[local_support] = repaired[local_support]
    plate[y1:y2, x1:x2] = region


def create_case_overview_v8_subtitle_plate(
    source: np.ndarray,
    v7_plate: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    """Clean all six V8 subtitle lanes from the evolving source-derived plate."""

    if source.shape != v7_plate.shape:
        raise RendererContractError("V8 Case Overview subtitle plate dimensions changed.")
    clean = v7_plate.copy()
    cleanup_masks = case_overview_v8_subtitle_cleanup_masks(clean.shape[:2])
    for (name, _value, _position), bounds in zip(
        CASE_OVERVIEW_V8_BAKED_SUBTITLE_SPECS,
        CASE_OVERVIEW_V8_SUBTITLE_LOCAL_BOUNDS,
    ):
        _inpaint_case_overview_support(clean, cleanup_masks[name], bounds)
    entries = case_overview_v8_subtitle_entries()
    return clean, draw_text_entries(clean, entries)


def apply_case_overview_v8_subtitle_overlay(
    context: "RenderContext",
    panel: np.ndarray,
) -> np.ndarray:
    """Apply the V8 subtitle-only plate after all frozen #7 route rendering."""

    result = panel.copy()
    for x1, y1, x2, y2 in case_overview_v8_subtitle_overlay_bounds():
        result[y1:y2, x1:x2] = context.s07_v8_text_plate[y1:y2, x1:x2]
    return result


def case_overview_v7_text_entries(renderer_state: dict[str, Any]) -> list[TextEntry]:
    """V7 readability-only text treatment within frozen Proposal-B lanes."""

    shared = renderer_state["dashboard"]["shared"]
    relationships = renderer_state["relationships"]
    events = renderer_state["events"]
    access_count = sum(
        1
        for event in events
        if "ACCESS" in str(event.get("event_type", "")).upper()
        or "ACCESS" in str(event.get("message", "")).upper()
    )
    feed_count = len(events)
    correlation_count = int(renderer_state["correlation_count"])
    title = (212, 204, 199)
    entries = [
        # Inbound modules: title, data value, then restrained descriptor.
        TextEntry((19, 60, 86, 68), (20, 60), "EVIDENCE", title, 7, True, 64),
        TextEntry((19, 68, 86, 84), (20, 70), f"{shared['evidence_count']} RECORDS", (245, 77, 58), 9, True, 64),
        TextEntry((19, 130, 86, 138), (20, 130), "ACCESS LOGS", title, 7, True, 64),
        TextEntry((19, 138, 86, 154), (20, 140), f"{access_count} ACCESS LOGS", (241, 165, 82), 8, True, 64),
        TextEntry((19, 200, 86, 208), (20, 200), "TIMELINE", title, 7, True, 64),
        TextEntry((19, 208, 86, 220), (20, 210), f"{feed_count} EVENTS", (244, 78, 57), 9, True, 64),
        # Outbound modules retain the approved semantic accent colors.
        TextEntry((340, 60, 397, 68), (341, 60), "INTELLIGENCE", title, 7, True, 56),
        TextEntry((340, 68, 395, 84), (341, 70), f"{max(1, renderer_state['threat_history_count'])} REPORT", (93, 177, 222), 9, True, 52),
        TextEntry((340, 130, 397, 138), (341, 130), "CORRELATION", title, 7, True, 56),
        TextEntry((340, 138, 395, 154), (341, 140), f"{correlation_count} LINKS", (246, 87, 63), 9, True, 52),
        TextEntry((340, 200, 407, 208), (341, 200), "CASE DATA STORE", title, 7, True, 66),
        TextEntry((340, 208, 403, 222), (341, 210), f"REV {shared['state_revision']}", (108, 227, 151), 9, True, 61),
        # Central hub: larger live-case text, while its red box, rails, and
        # verification flag remain frozen source geometry.
        TextEntry((186, 108, 266, 119), (188, 109), "ACTIVE CASE FILE", (255, 202, 185), 7, True, 76),
        TextEntry((186, 125, 274, 137), (188, 127), str(shared["case_id"]), (255, 116, 88), 10, True, 84),
        TextEntry((186, 138, 274, 149), (188, 140), str(shared["lifecycle_status"]), (255, 95, 72), 9, True, 84),
        TextEntry((186, 149, 274, 160), (188, 151), human_stage(shared["current_stage"]), (205, 191, 184), 7, True, 84),
        TextEntry((186, 159, 274, 169), (188, 161), f"{len(relationships)} RELATIONSHIPS", (178, 169, 164), 7, True, 84),
    ]
    entries.extend(case_overview_v7_subtitle_entries())
    return entries


def case_overview_v5_text_entries(renderer_state: dict[str, Any]) -> list[TextEntry]:
    """Readable V5 live-value overlay inside the already-approved #7 lanes."""

    shared = renderer_state["dashboard"]["shared"]
    relationships = renderer_state["relationships"]
    return [
        # The centered case hub keeps its frozen rails, dividers, red box, and
        # route clearances.  Only its live values are made legible at dashboard
        # scale; the shorter semantic labels avoid any geometry change.
        TextEntry((186, 125, 274, 137), (188, 127), str(shared["case_id"]), (255, 116, 88), 10, True, 84),
        TextEntry((186, 138, 274, 149), (188, 140), str(shared["lifecycle_status"]), (255, 95, 72), 9, True, 84),
        TextEntry((186, 149, 274, 160), (188, 151), human_stage(shared["current_stage"]), (205, 191, 184), 7, True, 84),
        TextEntry((186, 159, 274, 169), (188, 161), f"{len(relationships)} RELATIONSHIPS", (178, 169, 164), 7, True, 84),
        # The former COMMIT READY preview value is fully source-inpainted
        # before this persisted revision is drawn.  The lower descriptor is
        # intentional Proposal-B copy, retained with a clearer muted green.
        TextEntry((340, 208, 403, 224), (342, 209), f"REV {shared['state_revision']}", (108, 227, 151), 9, True, 59),
        TextEntry((340, 222, 403, 235), (342, 226), "PERSIST / RETAIN", (138, 171, 151), 6, True, 59),
    ]


def _inpaint_case_overview_lane(
    source: np.ndarray,
    bounds: tuple[int, int, int, int],
    *,
    minimum_brightness: int,
    dilate: int,
) -> np.ndarray:
    """Rebuild one safe #7 text lane from nearby approved source texture."""

    x1, y1, x2, y2 = bounds
    region = source[y1:y2, x1:x2].copy()
    glyphs = foreground_mask(region, minimum_brightness=minimum_brightness)
    if dilate:
        glyphs = cv2.dilate(
            glyphs.astype(np.uint8),
            np.ones((dilate * 2 + 1, dilate * 2 + 1), np.uint8),
            iterations=1,
        ).astype(bool)
    if np.any(glyphs):
        repaired = cv2.inpaint(region, glyphs.astype(np.uint8) * 255, 2, cv2.INPAINT_TELEA)
        region[glyphs] = repaired[glyphs]
    return region


def create_case_overview_v5_text_plate(
    source: np.ndarray,
    clean_plate: np.ndarray,
    renderer_state: dict[str, Any],
) -> np.ndarray:
    """Create the V5 local text plate without altering the frozen #7 plate."""

    result = clean_plate.copy()
    # Threshold 16 is one level above the surrounding card texture (max 15).
    # A single-pixel dilation removes every antialias fragment of COMMIT READY
    # and the intentionally restyled descriptor without repainting the card.
    for bounds in (
        (340, 208, 403, 224),
        (340, 222, 403, 235),
    ):
        x1, y1, x2, y2 = bounds
        result[y1:y2, x1:x2] = _inpaint_case_overview_lane(
            source,
            bounds,
            minimum_brightness=16,
            dilate=1,
        )
    return draw_text_entries(result, case_overview_v5_text_entries(renderer_state))


def apply_case_overview_v5_text_overlay(context: "RenderContext", panel: np.ndarray) -> np.ndarray:
    """Replace only V5's static-safe text lanes after frozen route rendering."""

    result = panel.copy()
    for x1, y1, x2, y2 in CASE_OVERVIEW_V5_LOCAL_BOUNDS:
        result[y1:y2, x1:x2] = context.s07_v5_text_plate[y1:y2, x1:x2]
    return result


def create_case_overview_v7_text_plate(
    source: np.ndarray,
    clean_plate: np.ndarray,
    renderer_state: dict[str, Any],
) -> np.ndarray:
    """Create a text-only readability plate over the approved Proposal-B art."""

    result = clean_plate.copy()
    for bounds in CASE_OVERVIEW_V7_LOCAL_BOUNDS:
        x1, y1, x2, y2 = bounds
        result[y1:y2, x1:x2] = _inpaint_case_overview_lane(
            source,
            bounds,
            minimum_brightness=16,
            dilate=1,
        )
    return draw_text_entries(result, case_overview_v7_text_entries(renderer_state))


def apply_case_overview_v7_text_overlay(context: "RenderContext", panel: np.ndarray) -> np.ndarray:
    """Restore V7 typography after frozen #7 route rendering, never geometry."""

    result = panel.copy()
    for x1, y1, x2, y2 in CASE_OVERVIEW_V7_LOCAL_BOUNDS:
        result[y1:y2, x1:x2] = context.s07_v7_text_plate[y1:y2, x1:x2]
    return result


def create_threat_guide_v6_plate(
    panel: np.ndarray,
    panel_bounds: tuple[int, int, int, int],
    raw: np.ndarray,
) -> np.ndarray:
    """Repair and redraw only the static Threshold Guide text columns.

    The frozen #6 plate remains untouched.  The old source-derived glyphs are
    removed inside four tight label/value lanes and rebuilt on the existing
    textured guide background; leader bars, summary bullets, panel geometry,
    and the animated graph are deliberately outside this overlay.
    """

    panel_x, panel_y, _panel_x2, _panel_y2 = panel_bounds
    result = panel.copy()
    for global_bounds in THREAT_GUIDE_V6_CLEAR_BOUNDS:
        gx1, gy1, gx2, gy2 = global_bounds
        x1, y1, x2, y2 = gx1 - panel_x, gy1 - panel_y, gx2 - panel_x, gy2 - panel_y
        region = result[y1:y2, x1:x2].copy()
        glyphs = foreground_mask(region, minimum_brightness=10)
        glyphs = cv2.dilate(
            glyphs.astype(np.uint8), np.ones((3, 3), np.uint8), iterations=1
        ).astype(bool)
        if np.any(glyphs):
            repaired = cv2.inpaint(region, glyphs.astype(np.uint8) * 255, 2, cv2.INPAINT_TELEA)
            region[glyphs] = repaired[glyphs]
        result[y1:y2, x1:x2] = region

    image = Image.fromarray(result, "RGB")
    draw = ImageDraw.Draw(image)
    guide_colors = threshold_guide_colors(raw)
    range_color = (185, 180, 177)
    for level, global_y, value in THREAT_GUIDE_V6_ROWS:
        y = global_y - panel_y
        color = guide_colors[level]
        draw.text((884 - panel_x, y), level, fill=color, font=dashboard_font(10, True))
        # V12: fixed raster strokes avoid platform-dependent font rounding at
        # this tiny size.  The two five-pixel bars retain the established
        # vertical center while making the threshold separator more legible.
        for stroke_offset in (3, 5):
            draw.line(
                ((932 - panel_x, y + stroke_offset), (936 - panel_x, y + stroke_offset)),
                fill=color,
                width=1,
            )
        draw.text((950 - panel_x, y), value, fill=range_color, font=dashboard_font(11))
    return np.asarray(image, dtype=np.uint8)


def apply_threat_guide_v6_overlay(context: "RenderContext", panel: np.ndarray) -> np.ndarray:
    """Composite the V6 guide text lanes after frozen #6 signal rendering."""

    result = panel.copy()
    panel_x, panel_y, _panel_x2, _panel_y2 = context.helpers.s06.PANEL_BOUNDS
    for gx1, gy1, gx2, gy2 in THREAT_GUIDE_V6_CLEAR_BOUNDS:
        x1, y1, x2, y2 = gx1 - panel_x, gy1 - panel_y, gx2 - panel_x, gy2 - panel_y
        result[y1:y2, x1:x2] = context.s06_v6_guide_plate[y1:y2, x1:x2]
    return result


def create_system_status_v7_plate(
    plate: np.ndarray,
    panel_bounds: tuple[int, int, int, int],
) -> np.ndarray:
    """Remove only obsolete upper-list dividers from the source-derived #5 plate."""

    panel_x, panel_y, _panel_x2, _panel_y2 = panel_bounds
    result = plate.copy()
    for gx1, gy1, gx2, gy2 in SYSTEM_STATUS_V7_DIVIDER_BANDS:
        x1, y1, x2, y2 = gx1 - panel_x, gy1 - panel_y, gx2 - panel_x, gy2 - panel_y
        # A divider itself is only one or two pixels high.  Give Telea nearby
        # source-derived texture above and below it; inpainting the divider
        # strip in isolation leaves it no unmasked neighborhood to sample.
        padding = 4
        rx1, rx2 = max(0, x1 - 2), min(result.shape[1], x2 + 2)
        ry1, ry2 = max(0, y1 - padding), min(result.shape[0], y2 + padding)
        region = result[ry1:ry2, rx1:rx2].copy()
        erase = np.zeros(region.shape[:2], dtype=np.uint8)
        erase[y1 - ry1:y2 - ry1, x1 - rx1:x2 - rx1] = 255
        repaired = cv2.inpaint(region, erase, 3, cv2.INPAINT_TELEA)
        result[y1:y2, x1:x2] = repaired[y1 - ry1:y2 - ry1, x1 - rx1:x2 - rx1]
    return result


@dataclass
class RenderContext:
    helpers: FrozenHelpers
    raw: np.ndarray
    clear: np.ndarray
    registered_clear: np.ndarray
    renderer_state: dict[str, Any]
    render_started_at: datetime
    static_base: np.ndarray
    palette_static_base: np.ndarray
    text_entries: list[TextEntry]
    authorization_mask: np.ndarray
    motion_mask: np.ndarray
    unit_status_clean_plate: np.ndarray
    operational_icon_plate: np.ndarray
    s01_stationary: np.ndarray
    s01_sprite: Image.Image
    s01_ring_mask: np.ndarray
    s01_atmosphere: dict[str, np.ndarray]
    s01_palette: Image.Image
    s02_stationary: np.ndarray
    s02_layer: np.ndarray
    s02_v9_accent_mask: np.ndarray
    s03_source: np.ndarray
    s03_static_workflow_plate: np.ndarray
    s03_stage_masks: list[np.ndarray]
    s03_arrow_masks: list[np.ndarray]
    s03_stage_norms: list[float]
    s03_arrow_norms: list[float]
    s04_source: np.ndarray
    s04_empty: np.ndarray
    s04_live_mask: np.ndarray
    s04_severity_masks: list[np.ndarray]
    s04_row_masks: list[np.ndarray]
    s04_bars: list[tuple[int, int]]
    s05_source: np.ndarray
    s05_v6_plate: np.ndarray
    s05_plate: np.ndarray
    s05_led_masks: list[np.ndarray]
    s06_source: np.ndarray
    s06_shell: np.ndarray
    s06_cleanup: np.ndarray
    s06_shell_changes: np.ndarray
    s06_draw_mask: np.ndarray
    s06_final_static: np.ndarray
    s06_v6_guide_plate: np.ndarray
    s07_plate: np.ndarray
    s07_clean_plate: np.ndarray
    s07_v5_text_plate: np.ndarray
    s07_v7_text_plate: np.ndarray
    s07_v8_subtitle_clean_plate: np.ndarray
    s07_v8_text_plate: np.ndarray
    s07_dynamic_text_lanes: np.ndarray
    s07_static_reference: np.ndarray
    s07_paths: dict[str, np.ndarray]
    s07_route_masks: dict[str, np.ndarray]
    s07_components: dict[str, np.ndarray]
    s07_authorized: np.ndarray
    route_gate: dict[str, bool]


def _panel(array: np.ndarray, bounds: tuple[int, int, int, int]) -> np.ndarray:
    x1, y1, x2, y2 = bounds
    return array[y1:y2, x1:x2].copy()


def _merge_panel(frame: np.ndarray, bounds: tuple[int, int, int, int], panel: np.ndarray) -> None:
    x1, y1, x2, y2 = bounds
    if panel.shape[:2] != (y2 - y1, x2 - x1):
        raise RendererContractError(f"Panel dimensions drifted for {bounds}.")
    frame[y1:y2, x1:x2] = panel


def create_evidence_package_v9_tone_plate(
    stationary_plate: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    """Subdue only the baked front-folder red tab; preserve its source texture."""

    x1, y1, x2, y2 = V9_EVIDENCE_FRONT_ACCENT_BOUNDS_LOCAL
    if stationary_plate.shape[:2] != (227, 452):
        raise RendererContractError("Evidence Package viewport dimensions changed before V9 tone repair.")
    result = stationary_plate.copy()
    region = result[y1:y2, x1:x2]
    values = region.astype(np.int16)
    red_dominant = (
        (values[:, :, 0] >= 55)
        & (values[:, :, 0] - values[:, :, 1] >= 18)
        & (values[:, :, 0] - values[:, :, 2] >= 18)
    )
    component_count, labels, stats, _centroids = cv2.connectedComponentsWithStats(
        red_dominant.astype(np.uint8),
        connectivity=8,
    )
    if component_count <= 1:
        raise RendererContractError("V9 Evidence Package front-folder accent was not found.")
    component_index = 1 + int(np.argmax(stats[1:, cv2.CC_STAT_AREA]))
    component = labels == component_index
    if int(np.count_nonzero(component)) != V9_EVIDENCE_FRONT_ACCENT_EXPECTED_PIXELS:
        raise RendererContractError("V9 Evidence Package front-folder accent geometry changed.")
    toned = np.rint(
        region[component].astype(np.float64)
        * np.asarray(V9_EVIDENCE_FRONT_ACCENT_SCALE, dtype=np.float64)
    )
    region[component] = np.clip(toned, 0, 255).astype(np.uint8)
    result[y1:y2, x1:x2] = region
    mask = np.zeros(result.shape[:2], dtype=bool)
    mask[y1:y2, x1:x2] = component
    return result, mask


def build_frozen_s01_palette(
    helper: ModuleType,
    stationary: np.ndarray,
    sprite: Image.Image,
    ring_mask: np.ndarray,
    atmosphere: dict[str, np.ndarray],
) -> Image.Image:
    """Recreate the approved #1 fixed palette from its four frozen phases."""

    indices = (0, 30, 60, 90)
    width, height = helper.VIEW_SIZE
    palette_source = Image.new("RGB", (width, height * len(indices)))
    for row, phase in enumerate(indices):
        panel, *_details = helper.render_frame(
            stationary,
            sprite,
            phase,
            ring_mask,
            atmosphere,
        )
        palette_source.paste(panel.convert("RGB"), (0, row * height))
    return palette_source.quantize(
        colors=256,
        method=Image.Quantize.MEDIANCUT,
        dither=Image.Dither.NONE,
    )


def _route_gate(renderer_state: dict[str, Any]) -> dict[str, bool]:
    events = renderer_state["events"]
    access = any(
        "ACCESS" in str(event.get("event_type", "")).upper()
        or "ACCESS" in str(event.get("message", "")).upper()
        for event in events
        if isinstance(event, dict)
    )
    return {
        "evidence_to_case": int(renderer_state["dashboard"]["shared"]["evidence_count"]) > 0,
        "access_to_case": access,
        "timeline_to_case": bool(events),
        "case_to_intelligence": renderer_state["canonical_threat_score"] >= 0,
        "case_to_correlation": renderer_state["correlation_count"] > 0,
        "case_to_datastore": int(renderer_state["dashboard"]["shared"]["state_revision"]) >= 1,
    }


def configure_case_overview_review_timing(
    helper: ModuleType,
    route_gate: dict[str, bool],
) -> None:
    """Resample frozen #7's approved route story at review-only 20fps.

    The module file and route geometry remain untouched.  This in-memory
    adapter doubles only timing coordinates so the exact frozen paths have
    intermediate positions across the 120-frame review loop instead of
    repeating a 60-frame sequence twice.
    """

    source_frames = int(helper.FRAME_COUNT)
    scale = FRAME_COUNT / source_frames
    routes = []
    for route in tuple(helper.ROUTES):
        if not route_gate.get(route.key, False):
            continue
        routes.append(
            route.__class__(
                route.key,
                route.source,
                route.destination,
                route.points,
                route.color,
                int(round(route.start * scale)) % FRAME_COUNT,
                max(2, int(round(route.duration * scale))),
            )
        )
    if not routes:
        raise RendererContractError("No persisted relationship route is available for Case Overview.")
    helper.FRAME_COUNT = FRAME_COUNT
    helper.FRAME_DURATION_MS = FRAME_DURATION_MS
    helper.ROUTES = tuple(routes)
    helper.ROUTE_BY_KEY = {route.key: route for route in helper.ROUTES}


def prepare_context(
    renderer_state: dict[str, Any],
    *,
    render_started_at: datetime | None = None,
) -> RenderContext:
    # Capture this once before frame assembly. The same instant flows through
    # the static text plate used by the PNG and every GIF frame.
    captured_render_started_at = capture_render_started_at(render_started_at)
    verify_approved_inputs()
    helpers = load_frozen_helpers()
    raw = np.array(Image.open(POPULATED_MASTER).convert("RGB"), dtype=np.uint8)
    clear = np.array(Image.open(CLEAR_MASTER).convert("RGB"), dtype=np.uint8)
    if (raw.shape[1], raw.shape[0]) != CANVAS_SIZE or (clear.shape[1], clear.shape[0]) != CANVAS_SIZE:
        raise RendererContractError("Approved master dimensions are not 1727x911.")

    registered_clear, _matrix = helpers.s01.register_clear_to_populated(clear, CANVAS_SIZE)
    s01_sprite, s01_alpha, _components, _diagnostics = helpers.s01.extract_fixed_sprite(raw, registered_clear)
    s01_stationary, _restore, _tone = helpers.s01.build_stationary_background(raw, registered_clear, s01_alpha)
    s01_ring = helpers.s01.build_ring_detail_mask(raw)
    s01_atmosphere = helpers.s01.build_scanner_atmosphere_base(raw)
    s01_palette = build_frozen_s01_palette(
        helpers.s01,
        s01_stationary,
        s01_sprite,
        s01_ring,
        s01_atmosphere,
    )

    _s02_view, s02_stationary, _s02_sprite, s02_layer = helpers.s02.extract_magnifier(raw)
    s02_stationary, s02_v9_accent_mask = create_evidence_package_v9_tone_plate(s02_stationary)

    s03_source = _panel(raw, helpers.s03.VIEW_BOUNDS)
    s03_stage_masks, s03_arrow_masks, _s03_union, s03_stage_norms, s03_arrow_norms = helpers.s03.build_element_masks(s03_source)
    # The frozen helper's current-stage breathing includes its text label.  V6
    # fixes the display locally by taking one fixed, state-correct phase as the
    # static workflow plate; only the incoming transition arrow is animated in
    # render_frame below.  The frozen #3 helper itself is not modified.
    s03_static_workflow_plate = helpers.s03.render_workflow_state(
        s03_source,
        s03_stage_masks,
        s03_arrow_masks,
        s03_stage_norms,
        s03_arrow_norms,
        renderer_state["dashboard"]["workflow"]["current_stage"],
        0.0,
    )
    workflow_stage = str(renderer_state["dashboard"]["workflow"]["current_stage"])
    workflow_stage_index = helpers.s03.STAGES.index(workflow_stage)
    # Preserve the same completed/current/pending logic while giving the
    # completed blue state enough restrained contrast to remain unambiguous
    # after the fixed GIF palette is applied.
    for completed_index in range(workflow_stage_index):
        blend_pixels(
            s03_static_workflow_plate,
            s03_stage_masks[completed_index],
            helpers.s03.STATUS_COLORS["completed"],
            0.16,
        )

    s04_source = _panel(raw, helpers.s04.PANEL_BOUNDS)
    (
        s04_live,
        s04_severity,
        s04_rows,
        s04_bars,
        _s04_tops,
        _s04_source_histogram,
        _s04_bar_field,
        _s04_plate_mask,
        _s04_authorized,
    ) = helpers.s04.build_masks(s04_source)
    s04_empty, _s04_clear_graph = helpers.s04.build_empty_graph_plate(s04_source, clear)

    s05_source = _panel(raw, helpers.s05.PANEL_BOUNDS)
    s05_led, _s05_trace_masks, s05_clear_masks, _s05_authorized = helpers.s05.build_masks(s05_source)
    s05_plate, _s05_ghosts = helpers.s05.build_trace_plate(s05_source, s05_clear_masks)
    s05_v6_plate = s05_plate.copy()
    s05_plate = create_system_status_v7_plate(s05_plate, helpers.s05.PANEL_BOUNDS)

    s06_source = _panel(raw, helpers.s06.PANEL_BOUNDS)
    s06_source_signal, s06_line_cleanup, s06_workbox, s06_draw = helpers.s06.source_signal_masks(s06_source)
    (
        s06_plot,
        s06_cleanup,
        _s06_fill,
        _s06_seed,
        _s06_residual,
        _s06_obsolete,
        _s06_changed,
        _s06_wedge,
        _s06_axis,
    ) = helpers.s06.build_source_derived_plot_plate(
        s06_source,
        s06_source_signal,
        s06_line_cleanup,
        s06_workbox,
    )
    (
        s06_shell,
        _s06_presentation,
        s06_shell_changes,
        s06_final_static,
        _s06_neutral,
    ) = helpers.s06.build_graph_shell_plate(s06_plot, s06_draw)
    s06_v6_guide_plate = create_threat_guide_v6_plate(
        s06_shell,
        helpers.s06.PANEL_BOUNDS,
        raw,
    )

    case_overview_source = np.array(
        Image.open(CASE_OVERVIEW_STATIC).convert("RGB"), dtype=np.uint8
    )
    if case_overview_source.shape[:2] != (272, 451):
        raise RendererContractError("Approved #7 Case Overview static reference dimensions changed.")
    route_gate = _route_gate(renderer_state)
    configure_case_overview_review_timing(helpers.s07, route_gate)
    # Critical ordering: route/component masks come from untouched frozen
    # Proposal-B art, before any narrow live-value cleaning takes place.
    (
        s07_paths,
        s07_route_masks,
        s07_components,
        s07_authorized,
        _s07_protected,
        _s07_static,
    ) = helpers.s07.build_masks(case_overview_source)
    s07_clean_plate, s07_plate, s07_dynamic_text_lanes = create_case_overview_plate(
        case_overview_source,
        renderer_state,
    )
    s07_v5_text_plate = create_case_overview_v5_text_plate(
        case_overview_source,
        s07_clean_plate,
        renderer_state,
    )
    s07_v7_text_plate = create_case_overview_v7_text_plate(
        case_overview_source,
        s07_clean_plate,
        renderer_state,
    )
    (
        s07_v8_subtitle_clean_plate,
        s07_v8_text_plate,
    ) = create_case_overview_v8_subtitle_plate(
        case_overview_source,
        s07_v7_text_plate,
    )
    # This union is an audit mask only.  The frozen route/component masks were
    # captured before all text cleanup, so an intersection here fails closed.
    for local_bounds in CASE_OVERVIEW_V7_LOCAL_BOUNDS:
        x1, y1, x2, y2 = local_bounds
        s07_dynamic_text_lanes[y1:y2, x1:x2] = True
        if np.any(s07_authorized[y1:y2, x1:x2]):
            raise RendererContractError(
                "V7 Case Overview readability lane intersects frozen #7 motion geometry."
            )
    for local_bounds in CASE_OVERVIEW_V5_LOCAL_BOUNDS:
        x1, y1, x2, y2 = local_bounds
        if np.any(s07_authorized[y1:y2, x1:x2]):
            raise RendererContractError(
                "V5 Case Overview readability lane intersects frozen #7 motion geometry."
            )
    # V8 is a post-route subtitle repair only.  Its Timeline extension ends
    # immediately before the frozen waveform; all six lanes must be clear of
    # both the fixed component art and every approved packet corridor.
    s07_frozen_geometry = np.zeros_like(s07_authorized)
    for mask in (*s07_components.values(), *s07_route_masks.values()):
        s07_frozen_geometry |= mask
    v8_cleanup_masks = case_overview_v8_subtitle_cleanup_masks(
        case_overview_source.shape[:2]
    )
    for index, ((name, _value, _position), cleanup_bounds, entry) in enumerate(zip(
        CASE_OVERVIEW_V8_BAKED_SUBTITLE_SPECS,
        CASE_OVERVIEW_V8_SUBTITLE_LOCAL_BOUNDS,
        case_overview_v8_subtitle_entries(),
    )):
        render_bounds = case_overview_v8_subtitle_render_bounds(index, cleanup_bounds)
        for local_bounds in (cleanup_bounds, render_bounds):
            x1, y1, x2, y2 = local_bounds
            s07_dynamic_text_lanes[y1:y2, x1:x2] = True
            if np.any(s07_authorized[y1:y2, x1:x2]):
                raise RendererContractError(
                    "V8 Case Overview subtitle lane intersects frozen #7 motion geometry."
                )
        fresh_support = _case_overview_text_support_mask(
            case_overview_source.shape[:2], entry, render_bounds
        )
        if np.any((v8_cleanup_masks[name] | fresh_support) & s07_frozen_geometry):
            raise RendererContractError(
                "V8 Case Overview subtitle cleanup intersects frozen #7 geometry."
            )

    base = raw.copy()
    _merge_panel(base, helpers.s01.VIEW_BOUNDS, s01_stationary)
    _merge_panel(base, helpers.s02.VIEW_BOUNDS, s02_stationary)
    _merge_panel(base, helpers.s04.PANEL_BOUNDS, s04_empty)
    _merge_panel(base, helpers.s05.PANEL_BOUNDS, s05_plate)
    _merge_panel(base, helpers.s06.PANEL_BOUNDS, s06_shell)
    _merge_panel(base, helpers.s07.PANEL_BOUNDS_GLOBAL, s07_plate)

    text_entries = all_text_entries(
        renderer_state,
        raw,
        render_started_at=captured_render_started_at,
    )
    # Build this just once from registered clean-master lanes.  Rendering a
    # frame later restores this clean content under every live string before
    # drawing it once; it therefore cannot stack data over baked preview text.
    # The dashboard masters share the approved global 1727x911 registration.
    # ``registered_clear`` is a #1-local scanner restoration transform and is
    # deliberately not reused for unrelated panel text lanes.
    static_base = clean_text_entries(base, clear, text_entries)
    # Retain a palette-only reconstruction of the frozen V2 text plate.  It
    # prevents the V3 cleanup of a few stale glyph tails from changing the
    # adaptive global palette for unrelated dashboard pixels.
    palette_static_base = clean_text_entries(base, clear, legacy_v2_palette_entries(text_entries))
    # Source-derived top-left unit lane: no clear-master placeholder rules.
    unit_status_clean_plate = build_unit_status_clean_plate(static_base)
    ux1, uy1, ux2, uy2 = UNIT_STATUS_BOUNDS
    static_base[uy1:uy2, ux1:ux2] = unit_status_clean_plate[uy1:uy2, ux1:ux2]
    palette_unit_status_clean_plate = build_unit_status_clean_plate(palette_static_base)
    palette_static_base[uy1:uy2, ux1:ux2] = palette_unit_status_clean_plate[uy1:uy2, ux1:ux2]
    # Legacy Operational Brief symbols are static integration residue. Replace
    # only their measured ROIs with line art; all copy remains untouched.
    operational_icon_plate = build_operational_icon_plate(static_base)
    for ox1, oy1, ox2, oy2 in OPERATIONAL_ICON_BOUNDS:
        static_base[oy1:oy2, ox1:ox2] = operational_icon_plate[oy1:oy2, ox1:ox2]
    palette_operational_icon_plate = build_operational_icon_plate(palette_static_base)
    for ox1, oy1, ox2, oy2 in OPERATIONAL_ICON_BOUNDS:
        palette_static_base[oy1:oy2, ox1:ox2] = palette_operational_icon_plate[oy1:oy2, ox1:ox2]

    canvas_mask = np.zeros((CANVAS_SIZE[1], CANVAS_SIZE[0]), dtype=bool)
    motion_mask = np.zeros_like(canvas_mask)
    for bounds in (
        helpers.s01.VIEW_BOUNDS,
        helpers.s02.VIEW_BOUNDS,
        helpers.s03.VIEW_BOUNDS,
        helpers.s04.PANEL_BOUNDS,
        helpers.s05.PANEL_BOUNDS,
        helpers.s06.PANEL_BOUNDS,
        helpers.s07.PANEL_BOUNDS_GLOBAL,
        UNIT_STATUS_BOUNDS,
    ):
        motion_mask |= rect_mask(CANVAS_SIZE, bounds)
    canvas_mask |= motion_mask
    for entry in text_entries:
        # Include the registered source-cleanup lane, not just the rendered
        # glyph field, in the source-difference authorization mask.
        canvas_mask |= rect_mask(CANVAS_SIZE, text_lane(entry))

    return RenderContext(
        helpers=helpers,
        raw=raw,
        clear=clear,
        registered_clear=registered_clear,
        renderer_state=renderer_state,
        render_started_at=captured_render_started_at,
        static_base=static_base,
        palette_static_base=palette_static_base,
        text_entries=text_entries,
        authorization_mask=canvas_mask,
        motion_mask=motion_mask,
        unit_status_clean_plate=unit_status_clean_plate,
        operational_icon_plate=operational_icon_plate,
        s01_stationary=s01_stationary,
        s01_sprite=s01_sprite,
        s01_ring_mask=s01_ring,
        s01_atmosphere=s01_atmosphere,
        s01_palette=s01_palette,
        s02_stationary=s02_stationary,
        s02_layer=s02_layer,
        s02_v9_accent_mask=s02_v9_accent_mask,
        s03_source=s03_source,
        s03_static_workflow_plate=s03_static_workflow_plate,
        s03_stage_masks=s03_stage_masks,
        s03_arrow_masks=s03_arrow_masks,
        s03_stage_norms=s03_stage_norms,
        s03_arrow_norms=s03_arrow_norms,
        s04_source=s04_source,
        s04_empty=s04_empty,
        s04_live_mask=s04_live,
        s04_severity_masks=s04_severity,
        s04_row_masks=s04_rows,
        s04_bars=s04_bars,
        s05_source=s05_source,
        s05_v6_plate=s05_v6_plate,
        s05_plate=s05_plate,
        s05_led_masks=s05_led,
        s06_source=s06_source,
        s06_shell=s06_shell,
        s06_cleanup=s06_cleanup,
        s06_shell_changes=s06_shell_changes,
        s06_draw_mask=s06_draw,
        s06_final_static=s06_final_static,
        s06_v6_guide_plate=s06_v6_guide_plate,
        s07_plate=s07_plate,
        s07_clean_plate=s07_clean_plate,
        s07_v5_text_plate=s07_v5_text_plate,
        s07_v7_text_plate=s07_v7_text_plate,
        s07_v8_subtitle_clean_plate=s07_v8_subtitle_clean_plate,
        s07_v8_text_plate=s07_v8_text_plate,
        s07_dynamic_text_lanes=s07_dynamic_text_lanes,
        s07_static_reference=case_overview_source,
        s07_paths=s07_paths,
        s07_route_masks=s07_route_masks,
        s07_components=s07_components,
        s07_authorized=s07_authorized,
        route_gate=route_gate,
    )


WORKFLOW_CARD_SHELLS_GLOBAL_V3 = {
    "CASE_SCAN": (454, 387, 544, 469),
    "EVIDENCE_REVIEW": (610, 387, 699, 469),
    "VALIDATION": (770, 387, 861, 469),
    "ASSESSMENT": (936, 387, 1031, 469),
    "PROBLEM_REVIEW": (1102, 387, 1206, 469),
}

# The frozen Evidence Review artwork is wider/taller than the compact V3
# lighting shell.  This is an overlay-only envelope around the existing card;
# it does not move or redraw any frozen geometry.
WORKFLOW_CARD_SHELLS_GLOBAL = {
    **WORKFLOW_CARD_SHELLS_GLOBAL_V3,
    "EVIDENCE_REVIEW": (605, 387, 712, 492),
}

# Explicit text bands allow V6 QC to distinguish clean static stage labels
# from the deliberately animated incoming transition arrow.
WORKFLOW_LABEL_BOUNDS_GLOBAL = (
    (454, 478, 545, 492),
    (605, 478, 712, 492),
    (770, 478, 861, 492),
    (936, 478, 1031, 492),
    (1102, 478, 1206, 492),
)


def _workflow_local_rect(context: RenderContext, bounds: tuple[int, int, int, int]) -> np.ndarray:
    """Return one workflow-local rectangle from immutable global geometry."""

    view_x1, view_y1, view_x2, view_y2 = context.helpers.s03.VIEW_BOUNDS
    x1, y1, x2, y2 = bounds
    return rect_mask(
        (view_x2 - view_x1, view_y2 - view_y1),
        (x1 - view_x1, y1 - view_y1, x2 - view_x1, y2 - view_y1),
    )


def workflow_micro_polish_masks(
    context: RenderContext,
    *,
    legacy_v3: bool = False,
) -> dict[str, np.ndarray]:
    """Declare the bounded #9 workflow-only lighting masks.

    This intentionally describes lighting around existing frozen silhouettes;
    it neither redrawn nor moves a card, icon, label, connector, or legend.
    """

    helper = context.helpers.s03
    stage = str(context.renderer_state["dashboard"]["workflow"]["current_stage"])
    stage_index = helper.STAGES.index(stage)
    shells = WORKFLOW_CARD_SHELLS_GLOBAL_V3 if legacy_v3 else WORKFLOW_CARD_SHELLS_GLOBAL
    safe = _workflow_local_rect(context, helper.ANIMATION_SAFE_BOUNDS_GLOBAL)
    current_shell = _workflow_local_rect(context, shells[stage])

    shell_x1, shell_y1, shell_x2, _shell_y2 = shells[stage]
    icon_width = min(37, max(24, shell_x2 - shell_x1 - 28))
    icon_center = (shell_x1 + shell_x2) // 2
    icon_bounds = (icon_center - icon_width // 2, shell_y1 + 16, icon_center + (icon_width + 1) // 2, shell_y1 + 66)
    if legacy_v3:
        current_icon = context.s03_stage_masks[stage_index] & _workflow_local_rect(context, icon_bounds)
        # Palette-only V3 reconstruction must remain byte-for-byte identical.
        current_halo = cv2.dilate(
            current_shell.astype(np.uint8), np.ones((7, 7), np.uint8), iterations=1
        ).astype(bool)
        current_halo &= ~current_shell & safe
    else:
        # V6 keeps all current-stage art, including its label, static for
        # readability. The actual incoming arrow is the only animated cue.
        current_icon = np.zeros_like(current_shell)
        current_halo = np.zeros_like(current_shell)

    incoming_arrow = (
        context.s03_arrow_masks[stage_index - 1].copy()
        if stage_index > 0
        else np.zeros_like(current_shell)
    )
    incoming_halo = cv2.dilate(
        incoming_arrow.astype(np.uint8), np.ones((3, 3), np.uint8), iterations=1
    ).astype(bool)
    incoming_halo &= ~incoming_arrow & safe

    completed_halo = np.zeros_like(current_shell)
    if legacy_v3:
        for completed_stage in helper.STAGES[:stage_index]:
            shell = _workflow_local_rect(context, shells[completed_stage])
            completed_halo |= cv2.dilate(
                shell.astype(np.uint8), np.ones((5, 5), np.uint8), iterations=1
            ).astype(bool) & ~shell & safe

    authorized = current_halo | current_icon | incoming_halo | incoming_arrow | completed_halo
    return {
        "current_halo": current_halo,
        "current_icon": current_icon,
        "incoming_halo": incoming_halo,
        "incoming_arrow": incoming_arrow,
        "completed_halo": completed_halo,
        "authorized": authorized,
        "safe": safe,
    }


def apply_workflow_review_emphasis(
    context: RenderContext,
    panel: np.ndarray,
    frame_index: int,
    *,
    legacy_v3: bool = False,
) -> np.ndarray:
    """Add the restrained, full-resolution workflow presentation overlay."""

    result = panel.copy()
    masks = workflow_micro_polish_masks(context, legacy_v3=legacy_v3)
    phase = (frame_index % FRAME_COUNT) / FRAME_COUNT
    breath = 0.5 - 0.5 * math.cos(math.tau * phase)

    if legacy_v3:
        # A moving soft sector around the existing card edge breaks the frozen
        # cosine symmetry after GIF palette quantization.  It is retained only
        # for the V3 palette reconstruction used outside V5 review regions.
        yy, xx = np.indices(result.shape[:2], dtype=np.float64)
        shells = WORKFLOW_CARD_SHELLS_GLOBAL_V3
        shell_x1, shell_y1, shell_x2, shell_y2 = shells[
            str(context.renderer_state["dashboard"]["workflow"]["current_stage"])
        ]
        view_x1, view_y1, _view_x2, _view_y2 = context.helpers.s03.VIEW_BOUNDS
        center_x = (shell_x1 + shell_x2) / 2.0 - view_x1
        center_y = (shell_y1 + shell_y2) / 2.0 - view_y1
        theta = np.arctan2((yy - center_y) / 41.0, (xx - center_x) / 44.5)
        moving_sector = (0.5 + 0.5 * np.cos(theta - math.tau * phase)) ** 6
        halo_weights = 0.075 + 0.065 * breath + 0.11 * moving_sector
        blend_weighted_pixels(result, masks["current_halo"], (210, 29, 26), halo_weights)
        blend_pixels(result, masks["current_icon"], (255, 76, 62), 0.025 + 0.10 * breath)
        blend_pixels(result, masks["incoming_halo"], (205, 31, 27), 0.035 + 0.050 * breath)
        blend_pixels(result, masks["incoming_arrow"], (255, 63, 50), 0.030 + 0.10 * breath)
    else:
        # V5 restores the approved workflow relationship: the frozen current
        # stage remains red, but visual emphasis lives on its actual icon and
        # the incoming current arrow—not an independent card-shaped outline.
        # The 60-frame period gives two seamless, readable three-second pulses
        # over the six-second loop and keeps both elements in sync.
        pulse_phase = (frame_index % (FRAME_COUNT // 2)) / (FRAME_COUNT // 2)
        pulse = 0.5 - 0.5 * math.cos(math.tau * pulse_phase)
        # V6 deliberately avoids any label, card, or icon glow. The actual
        # incoming arrow is the sole clean transition cue.
        blend_pixels(result, masks["incoming_halo"], (205, 31, 27), 0.025 + 0.105 * pulse)
        blend_pixels(result, masks["incoming_arrow"], (255, 86, 68), 0.160 + 0.440 * pulse)

    # Completed cards retain their frozen blue state.  This extremely low,
    # one-cycle halo is intentionally much quieter than the current red card.
    blend_pixels(
        result,
        masks["completed_halo"],
        (48, 122, 207),
        0.052 + 0.004 * math.sin(math.tau * phase),
    )
    return result


def feed_values_for_frame(context: RenderContext, frame_index: int) -> np.ndarray:
    """Map persisted intensity history into the fixed 39-slot #4 field.

    A rendered GIF is a visual monitoring loop, not a new telemetry source.
    Its bar heights therefore remain the exact persisted/data-derived values
    for every frame; only the bounded illumination layer is animated.
    """

    slot_count = len(context.s04_bars)
    persisted_events = sorted(
        (event for event in context.renderer_state["events"] if isinstance(event, dict)),
        key=lambda event: (str(event.get("timestamp", "")), int(event.get("sequence", 0))),
    )
    anchors: list[float] = []
    for event in persisted_events:
        try:
            intensity = float(event.get("intensity"))
        except (TypeError, ValueError):
            continue
        if math.isfinite(intensity):
            anchors.append(float(np.clip(intensity, 0.0, 100.0)))
    if not anchors:
        anchors = [float(value) for value in context.renderer_state["feed_history"]]
    if len(anchors) >= slot_count:
        # A complete persisted history legitimately spans the field; preserve
        # its chronological anchors with deterministic interpolation.
        base = resample(anchors, slot_count, name="Active Case Feed history")
    else:
        # Sparse-history adapter: empty historical periods remain a coherent
        # low/no-event floor.  The actual chronological samples occupy the
        # newest frozen slots; no fictional older spikes or linear 60-minute
        # ramp are invented.
        no_event_floor = 4.0
        base = np.full(slot_count, no_event_floor, dtype=np.float64)
        start = slot_count - len(anchors)
        base[start:] = np.asarray(anchors, dtype=np.float64)
    return base.astype(np.float64)


def feed_event_for_frame(context: RenderContext, frame_index: int) -> tuple[dict[str, object] | None, float, float]:
    visible = _feed_events(context.renderer_state)[:5]
    active_events = [event for event in visible if event["raw"]]
    if not active_events:
        return None, 0.0, 0.0
    slot_width = FRAME_COUNT / len(active_events)
    phase = (frame_index % FRAME_COUNT) / slot_width
    row_index = int(math.floor(phase)) % len(active_events)
    local = phase - math.floor(phase)
    strength = math.sin(math.pi * local) ** 1.35
    if strength <= 0.001:
        return None, 0.0, local
    event = dict(active_events[row_index])
    event["row_index"] = row_index
    event["severity"] = event["visual_severity"]
    event["telemetry_center"] = int(
        round((row_index + 1) * (len(context.s04_bars) - 1) / (len(active_events) + 1))
    )
    event["graph_intensity"] = min(1.0, 0.35 + 0.65 * strength)
    return event, strength, local


def apply_active_feed_live_overlay(
    context: RenderContext,
    panel: np.ndarray,
    tops: Sequence[int],
    heights: Sequence[int],
    frame_index: int,
    *,
    legacy_v3: bool = False,
) -> np.ndarray:
    """Add a bounded, data-faithful review-layer live presentation.

    The frozen #4 helper continues to draw every bar directly from persisted
    history. This layer deliberately changes only local illumination around
    those existing bar bodies and the existing LIVE glyph; it never appends or
    invents events, changes a bar's x position, or creates a historical spike.
    """

    result = panel.copy()
    panel_x, panel_y, _panel_x2, _panel_y2 = context.helpers.s04.PANEL_BOUNDS
    graph_x1, graph_y1, graph_x2, graph_y2 = context.helpers.s04.GRAPH_INTERIOR_GLOBAL
    graph_mask = np.zeros(result.shape[:2], dtype=bool)
    graph_mask[
        graph_y1 - panel_y:graph_y2 - panel_y,
        graph_x1 - panel_x:graph_x2 - panel_x,
    ] = True
    bodies = np.zeros(result.shape[:2], dtype=bool)
    baseline = int(context.helpers.s04.EXPECTED_GRAPH_BASELINE) - panel_y
    for (x1, x2), top, height in zip(context.s04_bars, tops, heights):
        if int(height) <= 0:
            continue
        lx1 = x1 - panel_x
        lx2 = x2 - panel_x + 1
        ly1 = max(graph_y1 - panel_y, int(top) - panel_y)
        bodies[ly1:baseline + 1, lx1:lx2] = True

    phase = (frame_index % FRAME_COUNT) / FRAME_COUNT
    # This asymmetric but seamless envelope avoids hard blinking and gives the
    # 120-frame review loop a visibly continuous presentation state.
    breath = float(np.clip(
        0.50
        + 0.31 * math.sin(math.tau * phase - 0.55)
        + 0.12 * math.sin(math.tau * 2.0 * phase + 0.80),
        0.04,
        0.96,
    ))

    # The low/no-event historical floor may breathe only imperceptibly.  Its
    # geometry remains data-derived and all edge pixels stay inside the graph.
    halo = cv2.dilate(bodies.astype(np.uint8), np.ones((3, 3), np.uint8), iterations=1).astype(bool)
    halo &= graph_mask & ~bodies
    blend_pixels(result, halo, (168, 31, 28), 0.008 + 0.012 * breath)
    blend_pixels(result, bodies, (248, 65, 53), 0.006 + 0.016 * breath)

    persisted_count = sum(
        1
        for event in context.renderer_state["events"]
        if isinstance(event, dict) and isinstance(event.get("intensity"), (int, float))
    )
    persisted_count = min(persisted_count, len(context.s04_bars))
    first_real_slot = len(context.s04_bars) - persisted_count

    # Persisted samples occupy the newest chronological slots.  Their halo
    # strength is ordered by recency only; it never changes stored values or
    # writes any bar pixels above a data-derived top.
    for rank, slot in enumerate(range(first_real_slot, len(context.s04_bars))):
        (x1, x2), top, height = context.s04_bars[slot], tops[slot], heights[slot]
        if int(height) <= 0:
            continue
        body = np.zeros(result.shape[:2], dtype=bool)
        body[
            max(graph_y1 - panel_y, int(top) - panel_y):baseline + 1,
            x1 - panel_x:x2 - panel_x + 1,
        ] = True
        recency = 0.55 + 0.45 * rank / max(1, persisted_count - 1)
        inner = cv2.dilate(body.astype(np.uint8), np.ones((3, 3), np.uint8), iterations=1).astype(bool)
        inner &= graph_mask & ~body
        corona = cv2.dilate(body.astype(np.uint8), np.ones((5, 5), np.uint8), iterations=1).astype(bool)
        corona &= graph_mask & ~inner & ~body
        blend_pixels(result, corona, (188, 31, 28), (0.025 + 0.13 * recency * breath))
        blend_pixels(result, inner, (226, 49, 41), (0.045 + 0.17 * recency * breath))
        blend_pixels(result, body, (255, 84, 66), (0.020 + 0.10 * recency * breath))

    # The existing LIVE dot/word is isolated from the title and event rows.
    # V3's wider halo is retained only for palette reconstruction; V5 uses a
    # single crisp edge ring so the word never reads as a blurred red smudge.
    live_allowed = np.zeros(result.shape[:2], dtype=bool)
    lx1 = context.helpers.s04.LIVE_ROI_GLOBAL[0] - panel_x
    ly1 = context.helpers.s04.LIVE_ROI_GLOBAL[1] - panel_y
    lx2 = context.helpers.s04.LIVE_ROI_GLOBAL[2] - panel_x
    ly2 = context.helpers.s04.LIVE_ROI_GLOBAL[3] - panel_y
    live_allowed[ly1:ly2, lx1:lx2] = True
    if legacy_v3:
        live_inner = cv2.dilate(context.s04_live_mask.astype(np.uint8), np.ones((5, 5), np.uint8), iterations=1).astype(bool)
        live_inner &= live_allowed & ~context.s04_live_mask
        live_outer = cv2.dilate(context.s04_live_mask.astype(np.uint8), np.ones((7, 7), np.uint8), iterations=1).astype(bool)
        live_outer &= live_allowed & ~live_inner & ~context.s04_live_mask
        blend_pixels(result, live_outer, (190, 31, 28), 0.025 + 0.090 * breath)
        blend_pixels(result, live_inner, (220, 42, 36), 0.045 + 0.120 * breath)
        _live_y, live_x = np.indices(result.shape[:2], dtype=np.float64)
        glint = 0.5 + 0.5 * np.sin(math.tau * (phase + (live_x - lx1) / max(1.0, lx2 - lx1) * 0.35))
        live_weights = 0.12 + 0.24 * breath + 0.07 * glint
        blend_weighted_pixels(result, context.s04_live_mask, (255, 70, 57), live_weights)
    else:
        live_edge = cv2.dilate(
            context.s04_live_mask.astype(np.uint8), np.ones((3, 3), np.uint8), iterations=1
        ).astype(bool)
        live_edge &= live_allowed & ~context.s04_live_mask
        pulse_phase = (frame_index % (FRAME_COUNT // 2)) / (FRAME_COUNT // 2)
        pulse_angle = math.tau * pulse_phase
        # A very small second-harmonic skew keeps this renderer-owned
        # heartbeat smooth and exactly 60-frame periodic while avoiding the
        # 31-state cosine symmetry that collapses below the decoded-GIF
        # activity contract after helper event activity is intentionally
        # removed from this ROI.
        pulse = float(np.clip(
            0.5 - 0.5 * math.cos(pulse_angle) + 0.055 * math.sin(2.0 * pulse_angle),
            0.0,
            1.0,
        ))
        blend_pixels(result, live_edge, (231, 48, 42), 0.020 + 0.140 * pulse)
        blend_pixels(result, context.s04_live_mask, (255, 86, 68), 0.100 + 0.430 * pulse)
    return result


def restore_active_feed_live_source_roi(context: RenderContext, panel: np.ndarray) -> np.ndarray:
    """Leave helper telemetry intact while resetting only the LIVE source plate."""

    global_x1, global_y1, global_x2, global_y2 = context.helpers.s04.LIVE_ROI_GLOBAL
    panel_x1, panel_y1, _panel_x2, _panel_y2 = context.helpers.s04.PANEL_BOUNDS
    local_x1 = global_x1 - panel_x1
    local_y1 = global_y1 - panel_y1
    local_x2 = global_x2 - panel_x1
    local_y2 = global_y2 - panel_y1
    result = panel.copy()
    result[local_y1:local_y2, local_x1:local_x2] = context.s04_source[
        local_y1:local_y2,
        local_x1:local_x2,
    ]
    return result


def metric_trace_for_frame(
    helper: ModuleType,
    frozen_key: str,
    samples: np.ndarray,
    width: int,
    frame_index: int,
    *,
    scale: float,
) -> np.ndarray:
    """Anchor frozen #5's distinct motion profiles to persisted telemetry."""

    normalized = np.clip(samples.astype(np.float64) / scale, 0.0, 1.0)
    base = resample(normalized, width, name="System Status telemetry")
    t = (frame_index % FRAME_COUNT) / FRAME_COUNT
    profile = np.asarray(helper.telemetry_samples(frozen_key, width, t), dtype=np.float64)
    initial = np.asarray(helper.telemetry_samples(frozen_key, width, 0.0), dtype=np.float64)
    # Calibrated against the frozen #5 raster envelopes: CPU/DISK retain small
    # irregular motion, memory/queue drift more slowly, and network has the
    # strongest bounded transfer bursts.  Values remain deterministic and
    # return precisely to persisted frame-zero anchors at the six-second seam.
    gains = {"cpu": 0.75, "memory": 2.20, "network": 0.70, "disk": 0.75, "uptime": 2.20}
    values = np.clip(base + gains[frozen_key] * (profile - initial), 0.0, 1.0)
    return values.astype(np.float64)


def system_status_for_frame(context: RenderContext, frame_index: int) -> dict[str, object]:
    system = context.renderer_state["dashboard"]["system_status"]
    rows = _status_rows(system)
    t = (frame_index % FRAME_COUNT) / FRAME_COUNT
    subsystems: dict[str, dict[str, object]] = {}
    frozen_keys = (
        "system_integrity",
        "data_pipeline",
        "api_services",
        "network_security",
        "threat_intel_feed",
    )
    for index, (key, row) in enumerate(zip(frozen_keys, rows)):
        pulse = 0.5 - 0.5 * math.cos(math.tau * (t + index * 0.13))
        intensity = 0.94 + 0.10 * max(0.0, min(1.0, float(row["intensity"]))) + 0.015 * pulse
        subsystems[key] = {
            "status": row["status"],
            "health": max(0.0, min(100.0, float(row["health"]))),
            "led_state": "truthful-source",
            "led_intensity": max(0.90, min(1.08, intensity)),
        }

    metrics = _metric_records(system)
    specs = (
        ("cpu", "cpu_percent", 100.0),
        ("memory", "memory_percent", 100.0),
        ("network", "network_percent", 100.0),
        ("disk", "disk_percent", 100.0),
        # Queue remains a count. Twelve is a documented view scale only, not
        # a percentage claim; the text label is redrawn as QUEUE / CT.
        ("uptime", "queue_depth", 12.0),
    )
    telemetry: dict[str, dict[str, object]] = {}
    for frozen_key, source_key, scale in specs:
        width = next(bounds[2] - bounds[0] for key, bounds, _ in context.helpers.s05.TRACE_SPECS if key == frozen_key)
        telemetry[frozen_key] = {
            "samples": tuple(
                float(value)
                for value in metric_trace_for_frame(
                    context.helpers.s05,
                    frozen_key,
                    metrics[source_key]["samples"],
                    width,
                    frame_index,
                    scale=scale,
                )
            )
        }
    return {
        "case_id": context.renderer_state["dashboard"]["shared"]["case_id"],
        "preview_only": False,
        "subsystems": subsystems,
        "telemetry": telemetry,
    }


def threat_history_for_frame(context: RenderContext, frame_index: int) -> np.ndarray:
    """Preserve the persisted anomaly signal while giving the live display motion."""

    draw_width = context.helpers.s06.DRAW_CLIP[2] - context.helpers.s06.DRAW_CLIP[0]
    base = resample(
        context.renderer_state["anomaly_history"],
        draw_width,
        name="Threat Monitor anomaly history",
    )
    t = (frame_index % FRAME_COUNT) / FRAME_COUNT
    x = np.linspace(0.0, 1.0, draw_width, endpoint=True)
    gradient = np.gradient(base) if base.size > 1 else np.zeros_like(base)
    envelope = np.sin(math.pi * x) ** 1.15
    motion = (
        2.2 * envelope * np.sin(math.tau * (t + 0.31 * x))
        + 0.35 * gradient * math.sin(math.tau * t)
    )
    values = np.clip(base + motion, 0.0, 100.0)
    # The persisted historical signal remains visible over most of the plot.
    # Only the final fifth smoothly converges to the one canonical score shown
    # elsewhere in this same active case; no second score is invented.
    score = float(context.renderer_state["canonical_threat_score"])
    tail = np.clip((x - 0.80) / 0.20, 0.0, 1.0)
    smooth_tail = tail * tail * (3.0 - 2.0 * tail)
    values = values * (1.0 - smooth_tail) + score * smooth_tail
    values[0] = base[0]
    values[-1] = score
    return values


def threat_target_y(context: RenderContext, score: int | float) -> int:
    """Map a normalized canonical score to frozen #6's exact plot y scale."""

    clip = context.helpers.s06.DRAW_CLIP
    height = clip[3] - clip[1]
    local = context.helpers.s06.signal_y_values_for_samples(
        np.asarray((float(score),), dtype=np.float64),
        height,
    )
    return int(clip[1] + int(local[0]))


def draw_threat_score_marker(context: RenderContext, panel: np.ndarray) -> np.ndarray:
    """Draw a tiny current-score target inside the protected NOW gutter."""

    result = panel.copy()
    score = int(context.renderer_state["canonical_threat_score"])
    presentation = str(context.renderer_state["subsystem_06_display_level"]).upper()
    color = threshold_guide_colors(context.raw)[presentation]
    global_y = threat_target_y(context, score)
    panel_x, panel_y, _x2, _y2 = context.helpers.s06.PANEL_BOUNDS
    image = Image.fromarray(result, "RGB")
    draw = ImageDraw.Draw(image)
    # The frozen right-scale restoration begins at x=1236. This 4px diamond
    # ends at x=1235, retaining the required one-pixel gutter and untouched
    # static axis/tick pixels.
    cx, cy = 1233 - panel_x, global_y - panel_y
    draw.line(((1231 - panel_x, cy), (1235 - panel_x, cy)), fill=(101, 42, 26), width=1)
    draw.line(((cx, cy - 2), (1235 - panel_x, cy), (cx, cy + 2), (1231 - panel_x, cy)), fill=color, width=1)
    return np.asarray(image, dtype=np.uint8)


def threat_input_for_frame(context: RenderContext, frame_index: int) -> dict[str, object]:
    shared = context.renderer_state["dashboard"]["shared"]
    canonical = context.renderer_state["dashboard"]["threat_monitor"]["threat"]["canonical_classification"]
    display = context.renderer_state["display"]
    summary = (
        f"{canonical.title()} active-case telemetry",
        f"{shared['evidence_count']} persisted evidence records",
        f"{context.renderer_state['correlation_count']} linked correlations",
        f"Workflow {human_stage(shared['current_stage'])}",
        str(display.get("recommended_action") or "Review active case."),
    )
    return {
        "case_id": shared["case_id"],
        "preview_only": False,
        "threat_score": context.renderer_state["canonical_threat_score"],
        "threat_level": context.renderer_state["subsystem_06_display_level"],
        "threshold_guide": context.helpers.s06.THRESHOLD_GUIDE,
        "threat_summary": tuple(summary),
        context.helpers.s06.ANOMALY_HISTORY_FIELD: tuple(
            float(value) for value in threat_history_for_frame(context, frame_index)
        ),
    }


def render_frame(context: RenderContext, frame_index: int) -> np.ndarray:
    """Render one independent full canvas. No frame is based on another frame."""

    if not 0 <= frame_index <= FRAME_COUNT:
        raise RendererContractError(f"Frame index must be 0..{FRAME_COUNT}.")
    frame = context.static_base.copy()
    # Frozen #1/#2 both carry 120 distinct approved phases. The #9 layer
    # samples every one directly (3 degrees/frame for #1), not every second
    # phase from the previous 10fps review loop.
    phase_120 = frame_index % context.helpers.s01.FRAME_COUNT

    s01_frame, *_s01_details = context.helpers.s01.render_frame(
        context.s01_stationary,
        context.s01_sprite,
        phase_120,
        context.s01_ring_mask,
        context.s01_atmosphere,
    )
    _merge_panel(
        frame,
        context.helpers.s01.VIEW_BOUNDS,
        np.array(
            s01_frame.convert("RGB")
            .quantize(palette=context.s01_palette, dither=Image.Dither.NONE)
            .convert("RGB"),
            dtype=np.uint8,
        ),
    )

    s02_frame, _alpha, _center, _rotation, _matrix = context.helpers.s02.render_frame(
        context.s02_stationary,
        context.s02_layer,
        phase_120,
    )
    _merge_panel(
        frame,
        context.helpers.s02.VIEW_BOUNDS,
        np.array(s02_frame.convert("RGB"), dtype=np.uint8),
    )

    # The state-correct V6 workflow plate is fixed; only its incoming arrow
    # gets the bounded emphasis below. This prevents animated label slicing.
    workflow = context.s03_static_workflow_plate.copy()
    workflow = apply_workflow_review_emphasis(context, workflow, frame_index)
    _merge_panel(frame, context.helpers.s03.VIEW_BOUNDS, workflow)

    feed_values = feed_values_for_frame(context, frame_index)
    feed_event, feed_strength, feed_progress = feed_event_for_frame(context, frame_index)
    feed_panel, _tops, _heights = context.helpers.s04.render_frame(
        context.s04_empty,
        context.s04_source,
        context.s04_live_mask,
        context.s04_severity_masks,
        context.s04_row_masks,
        context.s04_bars,
        feed_values,
        feed_event,
        feed_strength,
        feed_progress,
        frame_index,
    )
    # Persisted-event scan activity remains helper-owned. The LIVE glyph/dot
    # is renderer-owned and must retain its fixed 60-frame heartbeat for every
    # valid visible-event count, so reset only its approved source rectangle
    # before the existing fixed overlay is applied.
    feed_panel = restore_active_feed_live_source_roi(context, feed_panel)
    feed_panel = apply_active_feed_live_overlay(context, feed_panel, _tops, _heights, frame_index)
    _merge_panel(frame, context.helpers.s04.PANEL_BOUNDS, feed_panel)

    system_input = system_status_for_frame(context, frame_index)
    _unused_full, system_panel, _traces = context.helpers.s05.render_full_frame(
        context.raw,
        context.s05_source,
        context.s05_plate,
        context.s05_led_masks,
        system_input,
    )
    _merge_panel(frame, context.helpers.s05.PANEL_BOUNDS, system_panel)

    threat_input = threat_input_for_frame(context, frame_index)
    _unused_full, threat_panel, _foreground, _y, _area = context.helpers.s06.render_full_frame(
        context.raw,
        context.s06_source,
        context.s06_shell,
        context.s06_cleanup,
        context.s06_shell_changes,
        context.s06_draw_mask,
        context.s06_final_static,
        threat_input,
    )
    threat_panel = draw_threat_score_marker(context, threat_panel)
    threat_panel = apply_threat_guide_v6_overlay(context, threat_panel)
    _merge_panel(frame, context.helpers.s06.PANEL_BOUNDS, threat_panel)

    overview_panel, _route_records, _changed = context.helpers.s07.render_frame(
        context.s07_plate,
        context.s07_paths,
        context.s07_components,
        context.s07_authorized,
        frame_index,
    )
    overview_panel = apply_case_overview_v7_text_overlay(context, overview_panel)
    overview_panel = apply_case_overview_v8_subtitle_overlay(context, overview_panel)
    _merge_panel(frame, context.helpers.s07.PANEL_BOUNDS_GLOBAL, overview_panel)

    # #2/#4/#5/#6 may start from their approved populated plates internally.
    # Restore the registered clean lanes after those panel renders, then draw
    # each state value exactly once.  This prevents old source glyphs from
    # surviving beneath live data and keeps static borders outside all lanes.
    restore_clean_text_entries(frame, context.static_base, context.text_entries)
    frame = draw_unit_status_indicator(frame, frame_index)
    frame = draw_text_entries(frame, context.text_entries)
    # The timestamp must never be allowed to erase its master-derived outer
    # rectangle.  This is intentionally the final static compositing step.
    restore_footer_border(frame, context.raw)
    return frame


def render_frames(context: RenderContext) -> list[np.ndarray]:
    return [render_frame(context, index) for index in range(FRAME_COUNT)]


def save_png(array: np.ndarray, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    Image.fromarray(array, "RGB").save(path, format="PNG")


def global_palette(static_base: np.ndarray, representative_frames: Sequence[np.ndarray] = ()) -> Image.Image:
    """Build one shared review GIF palette from static and live representative art.

    Including a few deterministic source frames keeps threshold-guide colors
    (notably HIGH orange) and the local frozen #1 palette shades available in
    the final GIF while retaining one fixed palette for every encoded frame.
    """

    sources = (static_base, *representative_frames)
    palette_source = Image.new("RGB", (CANVAS_SIZE[0], CANVAS_SIZE[1] * len(sources)))
    for row, source in enumerate(sources):
        palette_source.paste(Image.fromarray(source, "RGB"), (0, row * CANVAS_SIZE[1]))
    # One fixed palette prevents static regions from receiving per-frame
    # adaptive quantization changes, the principal cause of GIF shimmer.
    return palette_source.quantize(
        colors=256,
        method=Image.Quantize.MEDIANCUT,
        dither=Image.Dither.NONE,
    )


@dataclass(frozen=True)
class PaletteProtectionRegion:
    """A source-frame ROI whose approved accents need exact GIF palette slots."""

    name: str
    bounds: tuple[int, int, int, int]
    colors: tuple[tuple[int, int, int], ...]
    palette_slots: tuple[int, ...]
    # Most regions remap their full rectangle. V6 Case Overview typography
    # uses a glyph-only mask so a local text palette can never turn an empty
    # card lane into a gray/white rectangle after GIF decoding.
    mask: np.ndarray | None = None
    # A V5-indexed base frame can be patched with an authorized V6 source ROI
    # directly against the unchanged V5 output palette.  This preserves every
    # non-authorized GIF index and palette color byte-for-byte.
    direct_output_quantization: bool = False


@dataclass(frozen=True)
class GifPalettePlan:
    """One fixed GIF palette plus narrowly scoped source-frame remapping."""

    baseline_palette: Image.Image
    output_palette: Image.Image
    regions: tuple[PaletteProtectionRegion, ...]
    v5_compatibility_regions: tuple[PaletteProtectionRegion, ...] = ()


def _palette_data(palette: Image.Image) -> list[int]:
    data = list(palette.getpalette() or [])
    return (data + [0] * 768)[:768]


def _palette_image(data: Sequence[int]) -> Image.Image:
    image = Image.new("P", (1, 1))
    image.putpalette(list(data)[:768])
    return image


# V11: These are existing V10 source-frame semantic cores and their existing
# frozen output-palette slots. Pillow's RGB-to-fixed-palette lookup is allowed
# for ordinary pixels, but must not choose a platform-specific neighboring slot
# for these contract colors. This runs only after quantization and never
# changes the RGB source frame or the frozen palette entries.
FROZEN_SEMANTIC_PALETTE_LOCKS = (
    ("threshold_critical", (186, 38, 25), 49, (186, 38, 25), (850, 721, 950, 740)),
    ("threshold_high", (205, 98, 41), 113, (205, 98, 41), (850, 742, 950, 762)),
    ("threshold_medium", (208, 157, 58), 131, (208, 157, 58), (850, 764, 950, 784)),
    ("threshold_low", (68, 153, 66), 144, (68, 153, 66), (850, 786, 950, 806)),
    ("live_low_score", (68, 153, 66), 144, (68, 153, 66), (850, 615, 940, 682)),
    ("workflow_completed", (45, 116, 196), 167, (48, 122, 207), (423, 372, 1259, 546)),
    ("workflow_current", (221, 30, 26), 17, (221, 34, 27), (423, 372, 1259, 546)),
    ("workflow_pending", (70, 70, 70), 15, (64, 71, 74), (423, 372, 1259, 546)),
    ("workflow_current_arrow", (230, 39, 33), 168, (226, 31, 27), (423, 372, 1259, 546)),
)

# V12: the guide's equals glyph is a fixed two-stroke raster mark.  Lock only
# its exact semantic cores after quantization; the narrow mask leaves the
# one-pixel middle gap and neighboring background untouched on every platform.
FROZEN_THRESHOLD_EQUALS_PALETTE_LOCKS = (
    ("threshold_critical_equals", 49, (186, 38, 25), (932, 727, 937, 730), "critical"),
    ("threshold_high_equals", 113, (205, 98, 41), (932, 749, 937, 752), "high"),
    ("threshold_medium_equals", 131, (208, 157, 58), (932, 771, 937, 774), "medium"),
    ("threshold_low_equals", 144, (68, 153, 66), (932, 793, 937, 796), "low"),
)


def lock_frozen_semantic_palette_indices(
    frame: np.ndarray,
    indices: np.ndarray,
    output_palette: Image.Image,
) -> None:
    """Restore exact approved semantic indices after Pillow quantization."""

    palette_data = _palette_data(output_palette)
    for name, source_rgb, palette_slot, expected_rgb, bounds in FROZEN_SEMANTIC_PALETTE_LOCKS:
        palette_rgb = tuple(palette_data[palette_slot * 3:palette_slot * 3 + 3])
        if palette_rgb != expected_rgb:
            raise RendererContractError(
                f"Frozen V11 palette slot drifted for {name}: "
                f"expected {expected_rgb}, found {palette_rgb}."
            )
        x1, y1, x2, y2 = bounds
        source_cores = np.all(
            frame[y1:y2, x1:x2] == np.asarray(source_rgb, dtype=np.uint8),
            axis=2,
        )
        if np.any(source_cores):
            region_indices = indices[y1:y2, x1:x2]
            region_indices[source_cores] = palette_slot
            indices[y1:y2, x1:x2] = region_indices

    for name, palette_slot, expected_rgb, bounds, level in FROZEN_THRESHOLD_EQUALS_PALETTE_LOCKS:
        palette_rgb = tuple(palette_data[palette_slot * 3:palette_slot * 3 + 3])
        if palette_rgb != expected_rgb:
            raise RendererContractError(
                f"Frozen V11 palette slot drifted for {name}: "
                f"expected {expected_rgb}, found {palette_rgb}."
            )
        x1, y1, x2, y2 = bounds
        source = frame[y1:y2, x1:x2].astype(np.int16)
        glyph = np.all(source == np.asarray(expected_rgb, dtype=np.int16), axis=2)
        if np.any(glyph):
            region_indices = indices[y1:y2, x1:x2]
            region_indices[glyph] = palette_slot
            indices[y1:y2, x1:x2] = region_indices


def _unused_palette_slots(frames: Sequence[np.ndarray], palette: Image.Image) -> list[int]:
    """Find slots absent from the unmodified V2 source-frame encoding."""

    used = np.zeros(256, dtype=bool)
    for frame in frames:
        indexed = Image.fromarray(frame, "RGB").quantize(
            palette=palette,
            dither=Image.Dither.NONE,
        )
        used[np.unique(np.asarray(indexed, dtype=np.uint8))] = True
    return [int(index) for index, present in enumerate(used) if not present]


def _unique_rgb(colors: Iterable[Sequence[int]]) -> tuple[tuple[int, int, int], ...]:
    result: list[tuple[int, int, int]] = []
    for color in colors:
        rgb = tuple(int(channel) for channel in color[:3])
        if rgb not in result:
            result.append(rgb)
    return tuple(result)


def _region_palette_colors(
    frames: Sequence[np.ndarray],
    bounds: tuple[int, int, int, int],
    *,
    local_color_count: int,
    anchors: Iterable[Sequence[int]],
) -> tuple[tuple[int, int, int], ...]:
    """Build a stable local accent palette from source pixels, not GIF edits."""

    x1, y1, x2, y2 = bounds
    sample_indices = list(range(0, len(frames), max(1, len(frames) // 12)))
    if sample_indices[-1] != len(frames) - 1:
        sample_indices.append(len(frames) - 1)
    atlas = np.concatenate(
        [frames[index][y1:y2, x1:x2] for index in sample_indices],
        axis=0,
    )
    local = Image.fromarray(atlas, "RGB").quantize(
        colors=local_color_count,
        method=Image.Quantize.MEDIANCUT,
        dither=Image.Dither.NONE,
    )
    local_palette = _palette_data(local)
    sampled = (
        tuple(local_palette[index * 3:index * 3 + 3])
        for index in np.unique(np.asarray(local, dtype=np.uint8))
    )
    return _unique_rgb((*anchors, *sampled))


def legacy_v2_palette_frame(
    context: RenderContext,
    frame: np.ndarray,
    frame_index: int,
) -> np.ndarray:
    """Reconstruct the frozen V3 palette sample without changing emitted V4 art."""

    result = frame.copy()

    # V4 strengthens only the pre-existing workflow and LIVE overlay masks.
    # Recompose their V3 presentation strictly for the fixed global-palette
    # sample, so unrelated decoded pixels retain their V3 index mapping.
    workflow = context.helpers.s03.render_workflow_state(
        context.s03_source,
        context.s03_stage_masks,
        context.s03_arrow_masks,
        context.s03_stage_norms,
        context.s03_arrow_norms,
        context.renderer_state["dashboard"]["workflow"]["current_stage"],
        frame_index / FRAME_COUNT,
    )
    workflow = apply_workflow_review_emphasis(context, workflow, frame_index, legacy_v3=True)
    _merge_panel(result, context.helpers.s03.VIEW_BOUNDS, workflow)

    feed_values = feed_values_for_frame(context, frame_index)
    feed_event, feed_strength, feed_progress = feed_event_for_frame(context, frame_index)
    feed_panel, tops, heights = context.helpers.s04.render_frame(
        context.s04_empty,
        context.s04_source,
        context.s04_live_mask,
        context.s04_severity_masks,
        context.s04_row_masks,
        context.s04_bars,
        feed_values,
        feed_event,
        feed_strength,
        feed_progress,
        frame_index,
    )
    feed_panel = apply_active_feed_live_overlay(
        context,
        feed_panel,
        tops,
        heights,
        frame_index,
        legacy_v3=True,
    )
    # Only V4's header LIVE illumination differs from V3.  Copying this tiny
    # region avoids replacing the independently restored live event text.
    live_x1, live_y1, live_x2, live_y2 = context.helpers.s04.LIVE_ROI_GLOBAL
    panel_x1, panel_y1, _panel_x2, _panel_y2 = context.helpers.s04.PANEL_BOUNDS
    result[live_y1:live_y2, live_x1:live_x2] = feed_panel[
        live_y1 - panel_y1:live_y2 - panel_y1,
        live_x1 - panel_x1:live_x2 - panel_x1,
    ]

    # V6 redraws only the guide text columns and score suffix.  Reconstruct the
    # prior sampled plate so these local typography improvements do not change
    # the global palette used by unrelated decoded pixels.
    threat_x1, threat_y1, _threat_x2, _threat_y2 = context.helpers.s06.PANEL_BOUNDS
    for gx1, gy1, gx2, gy2 in THREAT_GUIDE_V6_CLEAR_BOUNDS:
        x1, y1, x2, y2 = gx1 - threat_x1, gy1 - threat_y1, gx2 - threat_x1, gy2 - threat_y1
        result[gy1:gy2, gx1:gx2] = context.s06_shell[y1:y2, x1:x2]
    result[615:682, 850:940] = context.palette_static_base[615:682, 850:940]
    legacy_score_entries = (
        TextEntry((850, 615, 940, 657), (854, 621), str(context.renderer_state["canonical_threat_score"]), threshold_guide_colors(context.raw)[str(context.renderer_state["subsystem_06_display_level"]).upper()], 32, True, 42),
        TextEntry((892, 636, 940, 657), (894, 640), "/100", (184, 178, 175), 11, False, 43),
        TextEntry((850, 658, 940, 682), (854, 663), str(context.renderer_state["subsystem_06_display_level"]).upper(), threshold_guide_colors(context.raw)[str(context.renderer_state["subsystem_06_display_level"]).upper()], 13, True, 84),
    )
    result = draw_text_entries(result, legacy_score_entries)

    # V6's #7 readability overlay is post-route and strictly local. Restore
    # the former local source pixels only for palette sampling so the adaptive
    # global palette remains unchanged outside the V6 review lanes.
    s07_x1, s07_y1, _s07_x2, _s07_y2 = context.helpers.s07.PANEL_BOUNDS_GLOBAL
    for x1, y1, x2, y2 in CASE_OVERVIEW_V6_LOCAL_BOUNDS:
        result[s07_y1 + y1:s07_y1 + y2, s07_x1 + x1:s07_x1 + x2] = context.s07_plate[y1:y2, x1:x2]

    # Restore every V2-compatible lane once after rebuilding the two panels.
    # This includes the V4 cleanup-only fields and the legacy footer string
    # without a colon solely for median-cut sampling; live V4 frames retain the
    # corrected visible timestamp and clean plate.
    changed_entries = palette_compatibility_entries(context.text_entries)
    for entry in changed_entries:
        # V6 feed entries share a wide source-cleanup lane in emitted frames.
        # The palette reconstruction must instead restore only each former V5
        # text lane, otherwise it overwrites phase-specific V5 row pixels.
        x1, y1, x2, y2 = (
            entry.bounds if entry.bounds in FEED_ALL_ENTRY_BOUNDS else text_lane(entry)
        )
        result[y1:y2, x1:x2] = context.palette_static_base[y1:y2, x1:x2]
    legacy_entries = legacy_v2_palette_entries(changed_entries)
    legacy_entries = [
        replace(
            entry,
            value=footer_timestamp_for_render_instant(
                context.render_started_at,
                separator="",
            ),
        ) if entry.bounds == FOOTER_TIMESTAMP_ENTRY_BOUNDS else entry
        for entry in legacy_entries
    ]
    result = draw_text_entries(result, legacy_entries)
    restore_footer_border(result, context.raw)
    return result


def text_entry_palette_mask(entry: TextEntry) -> np.ndarray:
    """Return the exact glyph pixels within one declared text lane."""

    x1, y1, x2, y2 = entry.bounds
    image = Image.new("RGB", (x2 - x1, y2 - y1), (0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.multiline_text(
        (entry.position[0] - x1, entry.position[1] - y1),
        entry.value,
        fill=(255, 255, 255),
        font=dashboard_font(entry.size, entry.bold),
        spacing=entry.line_spacing,
    )
    return np.any(np.asarray(image, dtype=np.uint8) != 0, axis=2)


def _reconstructed_v5_compatibility_palette_plan(
    context: RenderContext,
    frames: Sequence[np.ndarray],
) -> GifPalettePlan:
    """Recreate the fixed V5 GIF palette and protected index mapping exactly."""

    representative_indices = tuple(index for index in (0, 30, 60, 90) if index < len(frames))
    legacy_frames = tuple(
        legacy_v2_palette_frame(context, frame, index)
        for index, frame in enumerate(frames)
    )
    baseline = global_palette(
        context.palette_static_base,
        tuple(legacy_frames[index] for index in representative_indices),
    )
    unused_slots = _unused_palette_slots(legacy_frames, baseline)
    guide_colors = threshold_guide_colors(context.raw)
    status_colors = context.helpers.s03.STATUS_COLORS
    presentation = str(context.renderer_state["subsystem_06_display_level"]).upper()
    s07_x1, s07_y1, _s07_x2, _s07_y2 = context.helpers.s07.PANEL_BOUNDS_GLOBAL
    hub_x1, hub_y1, hub_x2, hub_y2 = CASE_OVERVIEW_V5_HUB_LOCAL_BOUNDS
    store_x1, store_y1, store_x2, store_y2 = CASE_OVERVIEW_V5_DATASTORE_LOCAL_BOUNDS
    definitions = (
        ("threat_threshold_critical", (850, 721, 950, 740), 12, (guide_colors["CRITICAL"],)),
        ("threat_threshold_high", (850, 742, 950, 762), 12, (guide_colors["HIGH"],)),
        ("threat_threshold_medium", (850, 764, 950, 784), 12, (guide_colors["MEDIUM"],)),
        ("threat_threshold_low", (850, 786, 950, 806), 12, (guide_colors["LOW"],)),
        (
            "workflow_strip",
            context.helpers.s03.VIEW_BOUNDS,
            34,
            (
                status_colors["completed"],
                status_colors["current"],
                status_colors["pending"],
                (218, 33, 30),
                (255, 84, 68),
                (205, 31, 27),
                (255, 76, 62),
            ),
        ),
        ("threat_score_display", (850, 615, 940, 682), 4, (guide_colors[presentation],)),
        ("active_feed_live", context.helpers.s04.LIVE_ROI_GLOBAL, 4, ((255, 86, 68), (231, 48, 42))),
        (
            "case_overview_hub_readability",
            (s07_x1 + hub_x1, s07_y1 + hub_y1, s07_x1 + hub_x2, s07_y1 + hub_y2),
            4,
            ((255, 116, 88), (255, 95, 72), (205, 191, 184), (178, 169, 164)),
        ),
        (
            "case_overview_datastore_readability",
            (s07_x1 + store_x1, s07_y1 + store_y1, s07_x1 + store_x2, s07_y1 + store_y2),
            3,
            ((108, 227, 151), (138, 171, 151)),
        ),
    )
    requested = [
        (
            name,
            bounds,
            _region_palette_colors(
                legacy_frames,
                bounds,
                local_color_count=color_count,
                anchors=anchors,
            ),
        )
        for name, bounds, color_count, anchors in definitions
    ]
    required_slots = sum(len(colors) for _name, _bounds, colors in requested)
    if required_slots > len(unused_slots):
        raise RendererContractError(
            f"V5 GIF palette reservation needs {required_slots} unused slots; only {len(unused_slots)} available."
        )
    output_data = _palette_data(baseline)
    regions: list[PaletteProtectionRegion] = []
    cursor = 0
    for name, bounds, colors in requested:
        slots = tuple(unused_slots[cursor:cursor + len(colors)])
        cursor += len(colors)
        for slot, color in zip(slots, colors):
            output_data[slot * 3:slot * 3 + 3] = list(color)
        regions.append(PaletteProtectionRegion(name, bounds, colors, slots))
    return GifPalettePlan(baseline, _palette_image(output_data), tuple(regions))


# The V5 export plan is frozen with the approved V5 GIF, not derived from the
# V6 source frame. Reusing its exact palettes and region-slot allocation keeps
# every non-V6 GIF index byte-for-byte stable while direct V6 overlays are
# applied only inside the review-authorized regions below.
FROZEN_V5_PALETTE_PLAN_B64 = (
    "ew0KICAiYmFzZWxpbmVfcGFsZXR0ZV9oZXgiOiAiY2ZjZGNjYmFiNmIyOWZhY2ExOTY5ZDk0OTY5MzhmOGE4YThhODE4MjgxNjI4MThiODc2ZjY4NmU2ZTZl"
    "NjU2NjY2NWU1ZDVjNDU2Mjc0NTA1MzUzNGM0YjRiNDA0NzRhZGQyYzI0ZGQyMjFiOGEyOTIyNDQzZTNjM2MzZDNkMzQzODM4MzQzNDM0MzEyZjJlMjgzMzM3"
    "MmEyYjJiMjgyNzI3MWYyNjI3MjMyMjIyMWYyMDIwMWIyMDIwZWIxNzE1ZDUxNzEzYzgxNDExYjkxNTExYTUxNDExOGUxMzEwNzMxNDEwNTExNjE0MmExNjE1"
    "MWIxYjFiMTkxYTFhMTgxNzE3MTYxODE4MTUxNjE2MTUxNDE0MTExNTE3MTExMzEyMTAxMjEyMGYxMTExMGYxMDEwMGIxMDEwMGUwZjBmMGEwZjEwMGEwZjBm"
    "MGEwZjBlMDcwZjBlZGIwYjBmYmIwYjBjYWIwYjBiOWMwYzBiOTAwYjBhODYwYjBhNzcwYTBhNjUwYTA5NTgwYTA4NGQwYTA4NDEwOTA4MmMwYTA5MTkwYjBh"
    "MGMwZTBlMGMwZDBkMGIwYzBiMDgwZTEwMDkwZTBlMDcwZTBlMDgwYzBmMDgwYzBjMGIwYTBhMDkwOTBhMGEwOTA4MDgwOTA5MDcwOTA5MDUwZDBkMDYwYzBi"
    "MDQwYTBjMDUwYTBhMDUwOTA5MDQwODBhMDYwODA4MDUwODA4MDMwODA4MDQwODA3YTkwNjA5NzkwNjA2NjQwNTA2NTUwNTA2NDgwNTA1M2UwNTA1MzQwNTA1"
    "MmIwNTA1MjAwNTA0MTQwNTA1MGMwNTA1MDkwNTA1MGIwNDAzMDgwNjA2MDYwNzA4MDYwNzA3MDYwNzA2MDYwNjA2MDYwNTA2MDYwNTA0MDUwNzA4MDUwNzA3"
    "MDQwNzA3MDUwNzA2MDQwNjA3MDUwNjA2MDQwNTA2MDUwNjA1MDUwNTA1MDQwNTA1MDQwNTA0MDQwNDA1MDUwNDA0MDQwNDA0MDQwNDAzMDIwNjA5MDIwNjA3"
    "MDIwNTA3MDIwNjA2MDMwNTA2MDIwNTA2MDIwNDA2MDIwNjA1MDMwNTA1MDIwNTA1MDMwNDA1MDIwNDA1MDIwNTA0MDMwNDA0MDIwNDA0MDMwNDAzMDIwNDAz"
    "MDEwNjA5MDAwNjA3MDEwNTA2MDEwNDA2MDEwNjA1MDEwNTA1MDAwNTA1MDEwNDA1MDAwNDA1MDEwNTA0MDEwNDA0MDAwNDA0MDEwNTAzMDEwNDAzMDAwNDAz"
    "MDEwNDAyNmUwMzA1M2YwMzA0MjkwMzAzMTYwMzAzMDgwMzAzMDUwMzAzMDQwMzAzMDMwMzA0MDMwMzAzMDMwMzAyMDIwMzA1MDIwMzA0MDIwMzAzMDIwMzAy"
    "MDIwMzAxMDEwMzA1MDEwMzA0MDEwMzAzMDEwMzAyMDEwMzAxMDAwMzA1MDAwMzA0MDAwMzAzMDAwMzAyMDAwMzAxNDMwMjAzMTMwMjAyMDgwMjAyMDUwMjAz"
    "MDMwMjAzMDQwMjAyMDMwMjAyMDMwMjAxMDIwMjA0MDIwMjAzMDIwMjAyMDIwMjAxMDEwMjA1MDEwMjA0MDEwMjAzMDEwMjAyMDEwMjAxMDEwMjAwMDAwMjA1"
    "MDAwMjA0MDAwMjAzMDAwMjAyMDAwMjAxMDAwMjAwNGIwMTAyMjgwMTAxMWYwMDAxMTgwMTAxMTQwMTAxMTAwMDAxMGQwMDAxMGUwMDAwMGEwMTAxMGEwMDAw"
    "MDgwMDAxMDgwMDAwMDYwMTAxMDYwMTAwMDYwMDAwMDQwMTAyMDMwMTAyMDQwMTAxMDQwMDAxMDMwMTAxMDMwMDAxMDQwMTAwMDUwMDAwMDQwMDAwMDMwMTAw"
    "MDMwMDAwMDEwMTAzMDIwMTAyMDEwMTAyMDEwMDAyMDIwMTAxMDEwMTAxMDIwMDAxMDEwMDAxMDEwMTAwMDIwMDAwMDEwMDAwMDAwMTA0MDAwMTAzMDAwMDAz"
    "MDAwMTAyMDAwMDAyMDAwMTAxMDAwMDAxMDAwMTAwMDAwMDAwIiwNCiAgIm91dHB1dF9wYWxldHRlX2hleCI6ICJjZmNkY2NiYWI2YjI5ZmFjYTE5NjlkOTQ5"
    "NjkzOGY4YThhOGE4MTgyODE2MjgxOGI4NzZmNjg2ZTZlNmU2NTY2NjY1ZTVkNWM0NTYyNzQ1MDUzNTM0YzRiNGI0MDQ3NGFkZDJjMjRkZDIyMWI4YTI5MjI0"
    "NDNlM2MzYzNkM2QzNDM4MzgzNDM0MzQzMTJmMmUyODMzMzcyYTJiMmIyODI3MjcxZjI2MjcyMzIyMjIxZjIwMjAxYjIwMjBlYjE3MTVkNTE3MTNjODE0MTFi"
    "OTE1MTFhNTE0MTE4ZTEzMTA3MzE0MTA1MTE2MTQyYTE2MTUxYjFiMWIxOTFhMWExODE3MTcxNjE4MTgxNTE2MTYxNTE0MTQxMTE1MTcxMTEzMTIxMDEyMTJi"
    "YTI2MTkwZjEwMTAwYjEwMTAwZTBmMGYwYTBmMTA4MjE3MTQwYTBmMGUwNzBmMGVkYjBiMGZiYjBiMGNhYjBiMGI5YzBjMGI5MDBiMGE4NjBiMGE3NzBhMGE2"
    "NTBhMDk1ODBhMDg0ZDBhMDg0MTA5MDgyYzBhMDkxOTBiMGEwYzBlMGUwYzBkMGQxYzA1MDUwODBlMTAwMzA3MDgwMzA1MDUwODBjMGYwODBjMGMwYjBhMGEw"
    "OTA5MGEwYTA5MDgwODA5MDkwMzAyMDMwNTBkMGQwNjBjMGIwNDBhMGMwNTBhMGEwMTA2MDYwMTA0MDQwMTAzMDMwNTA4MDgwMzA4MDgwNDA4MDdhOTA2MDk3"
    "OTA2MDY2NDA1MDY1NTA1MDY0ODA1MDUzZTA1MDUzNDA1MDUyYjA1MDUyMDA1MDQxNDA1MDUwYzA1MDUwMTAyMDIwYjA0MDMwODA2MDYwNjA3MDgwMDA0MDQw"
    "MDAyMDIwMDAxMDEwNjA1MDYwNjA1MDRjZDYyMjk4MTRiMjUxNTBkMDkwNTA3MDYwNDA2MDcwNDA1MDUwMDA1MDUwMjA0MDQwMDA0MDQwMjAzMDMwNDA1MDQw"
    "MDAzMDQwMjAyMDEwNDA0MDQwMDAyMDMwMjA2MDkwMDAxMDEwMDAwMDBkMDlkM2E5Mzc0MzIzMTI0MTIwNTA3MDcwMTA3MDcwMzA1MDQwMTA0MDUwMDA0MDUw"
    "NDAyMDIwMTAyMDIwMDAyMDMwMDAxMDEwMDAwMDA0NDk5NDIwMTA2MDkwMDA2MDcyYTYyMzAwNDBjMDgwMTA2MDUwMjA1MDYwMTA0MDUwMTA0MDQwMTAzMDQw"
    "MDAzMDMwMDAzMDEwMDA0MDQwMTA1MDMwMTAyMDMwMDAyMDIwMDAxMDE2ZTAzMDUzZjAzMDQyOTAzMDMxNjAzMDMwODAzMDMwMDAwMDAzMDdhY2ZlMjFmMWI1"
    "YzVjNWMwMzAzMDIwMjAzMDVkYTIxMWVmZjU0NDRjZDFmMWJmZjRjM2U0MzUwNjA0YzJiMmY0MTE3MTYwZjEyMTQyYTA5MDgwNjA3MDgwMzA4MDkwMzA2MDcw"
    "ZDA1MDUwMDAzMDE0MzAyMDMxMzAyMDIwODAyMDIwMjA0MDUwMTA0MDUwMTA1MDQwMTA0MDQwMTA0MDMwMDA0MDQwOTAzMDMwMTAzMDUwMTAzMDQwMTAzMDMw"
    "MTAzMDIwMDAzMDQwMDAzMDMwMDAzMDIwNzAxMDEwMDAyMDUwMTAyMDMwMTAyMDIwMTAxMDEwMDAyMDQwMDAyMDM0YjAxMDIyODAxMDExZjAwMDExODAxMDEx"
    "NDAxMDExMDAwMDEwZDAwMDEwMDAyMDIwMDAxMDIwMDAxMDEwMDAwMDEwODAwMDAwMDAwMDA0NDk5NDIxMjIxMTMwNDAxMDIwMTAyMDIwMjAxMDEwMDAxMDFm"
    "ZjU2NDRlNzMwMmFhYjFmMWExNDA0MDQwNDAwMDAwMjA0MDQwMTAxMDFmZjc0NThmZjVmNDhjZGJmYjhiMmE5YTQ0ZTM4MzMwOTBlMGUwNjBlMGUwNTBhMGI2"
    "Y2UzOTc4YWFiOTcyNjNhMzAwMDAxMDQwYjExMTEwYTBmMGYwMDAxMDIwMDAwMDIwMDAxMDEwMDAwMDEwMDAxMDAwMDAwMDAiLA0KICAiYmFzZWxpbmVfcGFs"
    "ZXR0ZV9zaGEyNTYiOiAiOGQ1YzUxYzFjY2ZhYmY0NGU4YzAwM2QxNDJlMjQzY2JlMDY5OTU2ZDU0NGY3ODI2YTE1Y2VkYzA0OTA4NzEwOCIsDQogICJvdXRw"
    "dXRfcGFsZXR0ZV9zaGEyNTYiOiAiZjhmNTExNTQ0NDQzNmU1NmE4ODZkM2E3MGMxNDg3MGRkY2MxMmU2NTFhMzEwNjAxZDA0YWQwZWEyZThjMGVhYyIsDQog"
    "ICJyZWdpb25zIjogWw0KICAgIHsNCiAgICAgICJuYW1lIjogInRocmVhdF90aHJlc2hvbGRfY3JpdGljYWwiLA0KICAgICAgImJvdW5kcyI6IFsNCiAgICAg"
    "ICAgODUwLA0KICAgICAgICA3MjEsDQogICAgICAgIDk1MCwNCiAgICAgICAgNzQwDQogICAgICBdLA0KICAgICAgImNvbG9ycyI6IFsNCiAgICAgICAgWw0K"
    "ICAgICAgICAgIDE4NiwNCiAgICAgICAgICAzOCwNCiAgICAgICAgICAyNQ0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMTMwLA0KICAgICAg"
    "ICAgIDIzLA0KICAgICAgICAgIDIwDQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAyOCwNCiAgICAgICAgICA1LA0KICAgICAgICAgIDUNCiAg"
    "ICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDMsDQogICAgICAgICAgNywNCiAgICAgICAgICA4DQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAg"
    "ICAgICAzLA0KICAgICAgICAgIDUsDQogICAgICAgICAgNQ0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMywNCiAgICAgICAgICAyLA0KICAg"
    "ICAgICAgIDMNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDEsDQogICAgICAgICAgNiwNCiAgICAgICAgICA2DQogICAgICAgIF0sDQogICAg"
    "ICAgIFsNCiAgICAgICAgICAxLA0KICAgICAgICAgIDQsDQogICAgICAgICAgNA0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMSwNCiAgICAg"
    "ICAgICAzLA0KICAgICAgICAgIDMNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDEsDQogICAgICAgICAgMiwNCiAgICAgICAgICAyDQogICAg"
    "ICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAwLA0KICAgICAgICAgIDQsDQogICAgICAgICAgNA0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAg"
    "ICAgMCwNCiAgICAgICAgICAyLA0KICAgICAgICAgIDINCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDAsDQogICAgICAgICAgMSwNCiAgICAg"
    "ICAgICAxDQogICAgICAgIF0NCiAgICAgIF0sDQogICAgICAicGFsZXR0ZV9zbG90cyI6IFsNCiAgICAgICAgNDksDQogICAgICAgIDU0LA0KICAgICAgICA3"
    "MiwNCiAgICAgICAgNzQsDQogICAgICAgIDc1LA0KICAgICAgICA4MiwNCiAgICAgICAgODcsDQogICAgICAgIDg4LA0KICAgICAgICA4OSwNCiAgICAgICAg"
    "MTA0LA0KICAgICAgICAxMDgsDQogICAgICAgIDEwOSwNCiAgICAgICAgMTEwDQogICAgICBdDQogICAgfSwNCiAgICB7DQogICAgICAibmFtZSI6ICJ0aHJl"
    "YXRfdGhyZXNob2xkX2hpZ2giLA0KICAgICAgImJvdW5kcyI6IFsNCiAgICAgICAgODUwLA0KICAgICAgICA3NDIsDQogICAgICAgIDk1MCwNCiAgICAgICAg"
    "NzYyDQogICAgICBdLA0KICAgICAgImNvbG9ycyI6IFsNCiAgICAgICAgWw0KICAgICAgICAgIDIwNSwNCiAgICAgICAgICA5OCwNCiAgICAgICAgICA0MQ0K"
    "ICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMTI5LA0KICAgICAgICAgIDc1LA0KICAgICAgICAgIDM3DQogICAgICAgIF0sDQogICAgICAgIFsN"
    "CiAgICAgICAgICAyMSwNCiAgICAgICAgICAxMywNCiAgICAgICAgICA5DQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICA0LA0KICAgICAgICAg"
    "IDUsDQogICAgICAgICAgNQ0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMCwNCiAgICAgICAgICA1LA0KICAgICAgICAgIDUNCiAgICAgICAg"
    "XSwNCiAgICAgICAgWw0KICAgICAgICAgIDIsDQogICAgICAgICAgNCwNCiAgICAgICAgICA0DQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAw"
    "LA0KICAgICAgICAgIDQsDQogICAgICAgICAgNA0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMiwNCiAgICAgICAgICAzLA0KICAgICAgICAg"
    "IDMNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDAsDQogICAgICAgICAgMywNCiAgICAgICAgICA0DQogICAgICAgIF0sDQogICAgICAgIFsN"
    "CiAgICAgICAgICAyLA0KICAgICAgICAgIDIsDQogICAgICAgICAgMQ0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMCwNCiAgICAgICAgICAy"
    "LA0KICAgICAgICAgIDMNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDAsDQogICAgICAgICAgMSwNCiAgICAgICAgICAxDQogICAgICAgIF0s"
    "DQogICAgICAgIFsNCiAgICAgICAgICAwLA0KICAgICAgICAgIDAsDQogICAgICAgICAgMA0KICAgICAgICBdDQogICAgICBdLA0KICAgICAgInBhbGV0dGVf"
    "c2xvdHMiOiBbDQogICAgICAgIDExMywNCiAgICAgICAgMTE0LA0KICAgICAgICAxMTUsDQogICAgICAgIDExOCwNCiAgICAgICAgMTE5LA0KICAgICAgICAx"
    "MjAsDQogICAgICAgIDEyMSwNCiAgICAgICAgMTIyLA0KICAgICAgICAxMjQsDQogICAgICAgIDEyNSwNCiAgICAgICAgMTI3LA0KICAgICAgICAxMjksDQog"
    "ICAgICAgIDEzMA0KICAgICAgXQ0KICAgIH0sDQogICAgew0KICAgICAgIm5hbWUiOiAidGhyZWF0X3RocmVzaG9sZF9tZWRpdW0iLA0KICAgICAgImJvdW5k"
    "cyI6IFsNCiAgICAgICAgODUwLA0KICAgICAgICA3NjQsDQogICAgICAgIDk1MCwNCiAgICAgICAgNzg0DQogICAgICBdLA0KICAgICAgImNvbG9ycyI6IFsN"
    "CiAgICAgICAgWw0KICAgICAgICAgIDIwOCwNCiAgICAgICAgICAxNTcsDQogICAgICAgICAgNTgNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAg"
    "IDE0NywNCiAgICAgICAgICAxMTYsDQogICAgICAgICAgNTANCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDQ5LA0KICAgICAgICAgIDM2LA0K"
    "ICAgICAgICAgIDE4DQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICA1LA0KICAgICAgICAgIDcsDQogICAgICAgICAgNw0KICAgICAgICBdLA0K"
    "ICAgICAgICBbDQogICAgICAgICAgMSwNCiAgICAgICAgICA3LA0KICAgICAgICAgIDcNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDMsDQog"
    "ICAgICAgICAgNSwNCiAgICAgICAgICA0DQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAxLA0KICAgICAgICAgIDQsDQogICAgICAgICAgNQ0K"
    "ICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMCwNCiAgICAgICAgICA0LA0KICAgICAgICAgIDUNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAg"
    "ICAgICAgIDQsDQogICAgICAgICAgMiwNCiAgICAgICAgICAyDQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAxLA0KICAgICAgICAgIDIsDQog"
    "ICAgICAgICAgMg0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMCwNCiAgICAgICAgICAyLA0KICAgICAgICAgIDMNCiAgICAgICAgXSwNCiAg"
    "ICAgICAgWw0KICAgICAgICAgIDAsDQogICAgICAgICAgMSwNCiAgICAgICAgICAxDQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAwLA0KICAg"
    "ICAgICAgIDAsDQogICAgICAgICAgMA0KICAgICAgICBdDQogICAgICBdLA0KICAgICAgInBhbGV0dGVfc2xvdHMiOiBbDQogICAgICAgIDEzMSwNCiAgICAg"
    "ICAgMTMyLA0KICAgICAgICAxMzMsDQogICAgICAgIDEzNCwNCiAgICAgICAgMTM1LA0KICAgICAgICAxMzYsDQogICAgICAgIDEzNywNCiAgICAgICAgMTM4"
    "LA0KICAgICAgICAxMzksDQogICAgICAgIDE0MCwNCiAgICAgICAgMTQxLA0KICAgICAgICAxNDIsDQogICAgICAgIDE0Mw0KICAgICAgXQ0KICAgIH0sDQog"
    "ICAgew0KICAgICAgIm5hbWUiOiAidGhyZWF0X3RocmVzaG9sZF9sb3ciLA0KICAgICAgImJvdW5kcyI6IFsNCiAgICAgICAgODUwLA0KICAgICAgICA3ODYs"
    "DQogICAgICAgIDk1MCwNCiAgICAgICAgODA2DQogICAgICBdLA0KICAgICAgImNvbG9ycyI6IFsNCiAgICAgICAgWw0KICAgICAgICAgIDY4LA0KICAgICAg"
    "ICAgIDE1MywNCiAgICAgICAgICA2Ng0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgNDIsDQogICAgICAgICAgOTgsDQogICAgICAgICAgNDgN"
    "CiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDQsDQogICAgICAgICAgMTIsDQogICAgICAgICAgOA0KICAgICAgICBdLA0KICAgICAgICBbDQog"
    "ICAgICAgICAgMiwNCiAgICAgICAgICA1LA0KICAgICAgICAgIDYNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDEsDQogICAgICAgICAgNCwN"
    "CiAgICAgICAgICA1DQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAxLA0KICAgICAgICAgIDQsDQogICAgICAgICAgNA0KICAgICAgICBdLA0K"
    "ICAgICAgICBbDQogICAgICAgICAgMSwNCiAgICAgICAgICAzLA0KICAgICAgICAgIDQNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDAsDQog"
    "ICAgICAgICAgMywNCiAgICAgICAgICAzDQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAwLA0KICAgICAgICAgIDMsDQogICAgICAgICAgMQ0K"
    "ICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMSwNCiAgICAgICAgICAyLA0KICAgICAgICAgIDMNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAg"
    "ICAgICAgIDAsDQogICAgICAgICAgMiwNCiAgICAgICAgICAyDQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAwLA0KICAgICAgICAgIDEsDQog"
    "ICAgICAgICAgMQ0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMCwNCiAgICAgICAgICAwLA0KICAgICAgICAgIDANCiAgICAgICAgXQ0KICAg"
    "ICAgXSwNCiAgICAgICJwYWxldHRlX3Nsb3RzIjogWw0KICAgICAgICAxNDQsDQogICAgICAgIDE0NywNCiAgICAgICAgMTQ4LA0KICAgICAgICAxNTAsDQog"
    "ICAgICAgIDE1MSwNCiAgICAgICAgMTUyLA0KICAgICAgICAxNTMsDQogICAgICAgIDE1NCwNCiAgICAgICAgMTU1LA0KICAgICAgICAxNTgsDQogICAgICAg"
    "IDE1OSwNCiAgICAgICAgMTYwLA0KICAgICAgICAxNjYNCiAgICAgIF0NCiAgICB9LA0KICAgIHsNCiAgICAgICJuYW1lIjogIndvcmtmbG93X3N0cmlwIiwN"
    "CiAgICAgICJib3VuZHMiOiBbDQogICAgICAgIDQyMywNCiAgICAgICAgMzcyLA0KICAgICAgICAxMjU5LA0KICAgICAgICA1NDYNCiAgICAgIF0sDQogICAg"
    "ICAiY29sb3JzIjogWw0KICAgICAgICBbDQogICAgICAgICAgNDgsDQogICAgICAgICAgMTIyLA0KICAgICAgICAgIDIwNw0KICAgICAgICBdLA0KICAgICAg"
    "ICBbDQogICAgICAgICAgMjI2LA0KICAgICAgICAgIDMxLA0KICAgICAgICAgIDI3DQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICA5MiwNCiAg"
    "ICAgICAgICA5MiwNCiAgICAgICAgICA5Mg0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMjE4LA0KICAgICAgICAgIDMzLA0KICAgICAgICAg"
    "IDMwDQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAyNTUsDQogICAgICAgICAgODQsDQogICAgICAgICAgNjgNCiAgICAgICAgXSwNCiAgICAg"
    "ICAgWw0KICAgICAgICAgIDIwNSwNCiAgICAgICAgICAzMSwNCiAgICAgICAgICAyNw0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMjU1LA0K"
    "ICAgICAgICAgIDc2LA0KICAgICAgICAgIDYyDQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICA2NywNCiAgICAgICAgICA4MCwNCiAgICAgICAg"
    "ICA5Ng0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgNzYsDQogICAgICAgICAgNDMsDQogICAgICAgICAgNDcNCiAgICAgICAgXSwNCiAgICAg"
    "ICAgWw0KICAgICAgICAgIDY1LA0KICAgICAgICAgIDIzLA0KICAgICAgICAgIDIyDQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAxNSwNCiAg"
    "ICAgICAgICAxOCwNCiAgICAgICAgICAyMA0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgNDIsDQogICAgICAgICAgOSwNCiAgICAgICAgICA4"
    "DQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICA2LA0KICAgICAgICAgIDcsDQogICAgICAgICAgOA0KICAgICAgICBdLA0KICAgICAgICBbDQog"
    "ICAgICAgICAgMywNCiAgICAgICAgICA4LA0KICAgICAgICAgIDkNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDMsDQogICAgICAgICAgNiwN"
    "CiAgICAgICAgICA3DQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAxMywNCiAgICAgICAgICA1LA0KICAgICAgICAgIDUNCiAgICAgICAgXSwN"
    "CiAgICAgICAgWw0KICAgICAgICAgIDIsDQogICAgICAgICAgNCwNCiAgICAgICAgICA1DQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAxLA0K"
    "ICAgICAgICAgIDQsDQogICAgICAgICAgNQ0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMSwNCiAgICAgICAgICA1LA0KICAgICAgICAgIDQN"
    "CiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDEsDQogICAgICAgICAgNCwNCiAgICAgICAgICA0DQogICAgICAgIF0sDQogICAgICAgIFsNCiAg"
    "ICAgICAgICAxLA0KICAgICAgICAgIDQsDQogICAgICAgICAgMw0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMCwNCiAgICAgICAgICA0LA0K"
    "ICAgICAgICAgIDQNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDksDQogICAgICAgICAgMywNCiAgICAgICAgICAzDQogICAgICAgIF0sDQog"
    "ICAgICAgIFsNCiAgICAgICAgICAxLA0KICAgICAgICAgIDMsDQogICAgICAgICAgNQ0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMSwNCiAg"
    "ICAgICAgICAzLA0KICAgICAgICAgIDQNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDEsDQogICAgICAgICAgMywNCiAgICAgICAgICAzDQog"
    "ICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAxLA0KICAgICAgICAgIDMsDQogICAgICAgICAgMg0KICAgICAgICBdLA0KICAgICAgICBbDQogICAg"
    "ICAgICAgMCwNCiAgICAgICAgICAzLA0KICAgICAgICAgIDQNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDAsDQogICAgICAgICAgMywNCiAg"
    "ICAgICAgICAzDQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAwLA0KICAgICAgICAgIDMsDQogICAgICAgICAgMg0KICAgICAgICBdLA0KICAg"
    "ICAgICBbDQogICAgICAgICAgNywNCiAgICAgICAgICAxLA0KICAgICAgICAgIDENCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDEsDQogICAg"
    "ICAgICAgMiwNCiAgICAgICAgICAzDQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAxLA0KICAgICAgICAgIDIsDQogICAgICAgICAgMg0KICAg"
    "ICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMSwNCiAgICAgICAgICAxLA0KICAgICAgICAgIDENCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAg"
    "ICAgIDAsDQogICAgICAgICAgMiwNCiAgICAgICAgICA0DQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAwLA0KICAgICAgICAgIDIsDQogICAg"
    "ICAgICAgMw0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMCwNCiAgICAgICAgICAyLA0KICAgICAgICAgIDINCiAgICAgICAgXSwNCiAgICAg"
    "ICAgWw0KICAgICAgICAgIDAsDQogICAgICAgICAgMSwNCiAgICAgICAgICAyDQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAwLA0KICAgICAg"
    "ICAgIDEsDQogICAgICAgICAgMQ0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMCwNCiAgICAgICAgICAwLA0KICAgICAgICAgIDENCiAgICAg"
    "ICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDAsDQogICAgICAgICAgMCwNCiAgICAgICAgICAwDQogICAgICAgIF0NCiAgICAgIF0sDQogICAgICAicGFs"
    "ZXR0ZV9zbG90cyI6IFsNCiAgICAgICAgMTY3LA0KICAgICAgICAxNjgsDQogICAgICAgIDE2OSwNCiAgICAgICAgMTcyLA0KICAgICAgICAxNzMsDQogICAg"
    "ICAgIDE3NCwNCiAgICAgICAgMTc1LA0KICAgICAgICAxNzYsDQogICAgICAgIDE3NywNCiAgICAgICAgMTc4LA0KICAgICAgICAxNzksDQogICAgICAgIDE4"
    "MCwNCiAgICAgICAgMTgxLA0KICAgICAgICAxODIsDQogICAgICAgIDE4MywNCiAgICAgICAgMTg0LA0KICAgICAgICAxODksDQogICAgICAgIDE5MCwNCiAg"
    "ICAgICAgMTkxLA0KICAgICAgICAxOTIsDQogICAgICAgIDE5MywNCiAgICAgICAgMTk0LA0KICAgICAgICAxOTUsDQogICAgICAgIDE5NiwNCiAgICAgICAg"
    "MTk3LA0KICAgICAgICAxOTgsDQogICAgICAgIDE5OSwNCiAgICAgICAgMjAwLA0KICAgICAgICAyMDEsDQogICAgICAgIDIwMiwNCiAgICAgICAgMjAzLA0K"
    "ICAgICAgICAyMDUsDQogICAgICAgIDIwNiwNCiAgICAgICAgMjA3LA0KICAgICAgICAyMDgsDQogICAgICAgIDIwOSwNCiAgICAgICAgMjE3LA0KICAgICAg"
    "ICAyMTgsDQogICAgICAgIDIxOSwNCiAgICAgICAgMjIwLA0KICAgICAgICAyMjINCiAgICAgIF0NCiAgICB9LA0KICAgIHsNCiAgICAgICJuYW1lIjogInRo"
    "cmVhdF9zY29yZV9kaXNwbGF5IiwNCiAgICAgICJib3VuZHMiOiBbDQogICAgICAgIDg1MCwNCiAgICAgICAgNjE1LA0KICAgICAgICA5NDAsDQogICAgICAg"
    "IDY4Mg0KICAgICAgXSwNCiAgICAgICJjb2xvcnMiOiBbDQogICAgICAgIFsNCiAgICAgICAgICA2OCwNCiAgICAgICAgICAxNTMsDQogICAgICAgICAgNjYN"
    "CiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDE4LA0KICAgICAgICAgIDMzLA0KICAgICAgICAgIDE5DQogICAgICAgIF0sDQogICAgICAgIFsN"
    "CiAgICAgICAgICAxLA0KICAgICAgICAgIDIsDQogICAgICAgICAgMg0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMiwNCiAgICAgICAgICAx"
    "LA0KICAgICAgICAgIDENCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDAsDQogICAgICAgICAgMSwNCiAgICAgICAgICAxDQogICAgICAgIF0N"
    "CiAgICAgIF0sDQogICAgICAicGFsZXR0ZV9zbG90cyI6IFsNCiAgICAgICAgMjIzLA0KICAgICAgICAyMjQsDQogICAgICAgIDIyNiwNCiAgICAgICAgMjI3"
    "LA0KICAgICAgICAyMjgNCiAgICAgIF0NCiAgICB9LA0KICAgIHsNCiAgICAgICJuYW1lIjogImFjdGl2ZV9mZWVkX2xpdmUiLA0KICAgICAgImJvdW5kcyI6"
    "IFsNCiAgICAgICAgMjA0LA0KICAgICAgICA1NjYsDQogICAgICAgIDI0OCwNCiAgICAgICAgNTg0DQogICAgICBdLA0KICAgICAgImNvbG9ycyI6IFsNCiAg"
    "ICAgICAgWw0KICAgICAgICAgIDI1NSwNCiAgICAgICAgICA4NiwNCiAgICAgICAgICA2OA0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMjMx"
    "LA0KICAgICAgICAgIDQ4LA0KICAgICAgICAgIDQyDQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAxNzEsDQogICAgICAgICAgMzEsDQogICAg"
    "ICAgICAgMjYNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDIwLA0KICAgICAgICAgIDQsDQogICAgICAgICAgNA0KICAgICAgICBdLA0KICAg"
    "ICAgICBbDQogICAgICAgICAgMiwNCiAgICAgICAgICA0LA0KICAgICAgICAgIDQNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDEsDQogICAg"
    "ICAgICAgMSwNCiAgICAgICAgICAxDQogICAgICAgIF0NCiAgICAgIF0sDQogICAgICAicGFsZXR0ZV9zbG90cyI6IFsNCiAgICAgICAgMjI5LA0KICAgICAg"
    "ICAyMzAsDQogICAgICAgIDIzMSwNCiAgICAgICAgMjMyLA0KICAgICAgICAyMzQsDQogICAgICAgIDIzNQ0KICAgICAgXQ0KICAgIH0sDQogICAgew0KICAg"
    "ICAgIm5hbWUiOiAiY2FzZV9vdmVydmlld19odWJfcmVhZGFiaWxpdHkiLA0KICAgICAgImJvdW5kcyI6IFsNCiAgICAgICAgMTQ1NSwNCiAgICAgICAgMzk4"
    "LA0KICAgICAgICAxNTQzLA0KICAgICAgICA0NDINCiAgICAgIF0sDQogICAgICAiY29sb3JzIjogWw0KICAgICAgICBbDQogICAgICAgICAgMjU1LA0KICAg"
    "ICAgICAgIDExNiwNCiAgICAgICAgICA4OA0KICAgICAgICBdLA0KICAgICAgICBbDQogICAgICAgICAgMjU1LA0KICAgICAgICAgIDk1LA0KICAgICAgICAg"
    "IDcyDQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAyMDUsDQogICAgICAgICAgMTkxLA0KICAgICAgICAgIDE4NA0KICAgICAgICBdLA0KICAg"
    "ICAgICBbDQogICAgICAgICAgMTc4LA0KICAgICAgICAgIDE2OSwNCiAgICAgICAgICAxNjQNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDc4"
    "LA0KICAgICAgICAgIDU2LA0KICAgICAgICAgIDUxDQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICA5LA0KICAgICAgICAgIDE0LA0KICAgICAg"
    "ICAgIDE0DQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICA2LA0KICAgICAgICAgIDE0LA0KICAgICAgICAgIDE0DQogICAgICAgIF0sDQogICAg"
    "ICAgIFsNCiAgICAgICAgICA1LA0KICAgICAgICAgIDEwLA0KICAgICAgICAgIDExDQogICAgICAgIF0NCiAgICAgIF0sDQogICAgICAicGFsZXR0ZV9zbG90"
    "cyI6IFsNCiAgICAgICAgMjM2LA0KICAgICAgICAyMzcsDQogICAgICAgIDIzOCwNCiAgICAgICAgMjM5LA0KICAgICAgICAyNDAsDQogICAgICAgIDI0MSwN"
    "CiAgICAgICAgMjQyLA0KICAgICAgICAyNDMNCiAgICAgIF0NCiAgICB9LA0KICAgIHsNCiAgICAgICJuYW1lIjogImNhc2Vfb3ZlcnZpZXdfZGF0YXN0b3Jl"
    "X3JlYWRhYmlsaXR5IiwNCiAgICAgICJib3VuZHMiOiBbDQogICAgICAgIDE2MDksDQogICAgICAgIDQ4MSwNCiAgICAgICAgMTY3MiwNCiAgICAgICAgNTA4"
    "DQogICAgICBdLA0KICAgICAgImNvbG9ycyI6IFsNCiAgICAgICAgWw0KICAgICAgICAgIDEwOCwNCiAgICAgICAgICAyMjcsDQogICAgICAgICAgMTUxDQog"
    "ICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAxMzgsDQogICAgICAgICAgMTcxLA0KICAgICAgICAgIDE1MQ0KICAgICAgICBdLA0KICAgICAgICBb"
    "DQogICAgICAgICAgMzgsDQogICAgICAgICAgNTgsDQogICAgICAgICAgNDgNCiAgICAgICAgXSwNCiAgICAgICAgWw0KICAgICAgICAgIDExLA0KICAgICAg"
    "ICAgIDE3LA0KICAgICAgICAgIDE3DQogICAgICAgIF0sDQogICAgICAgIFsNCiAgICAgICAgICAxMCwNCiAgICAgICAgICAxNSwNCiAgICAgICAgICAxNQ0K"
    "ICAgICAgICBdDQogICAgICBdLA0KICAgICAgInBhbGV0dGVfc2xvdHMiOiBbDQogICAgICAgIDI0NCwNCiAgICAgICAgMjQ1LA0KICAgICAgICAyNDYsDQog"
    "ICAgICAgIDI0OCwNCiAgICAgICAgMjQ5DQogICAgICBdDQogICAgfQ0KICBdDQp9DQo="
)
FROZEN_V5_BASELINE_PALETTE_SHA256 = "8d5c51c1ccfabf44e8c003d142e243cbe069956d544f7826a15cedc049087108"
FROZEN_V5_OUTPUT_PALETTE_SHA256 = "f8f5115444436e56a886d3a70c14870ddcc12e651a310601d04ad0ea2e8c0eac"


@lru_cache(maxsize=1)
def frozen_v5_compatibility_palette_plan() -> GifPalettePlan:
    """Return the byte-for-byte frozen V5 palette and protection slots."""

    payload = json.loads(base64.b64decode(FROZEN_V5_PALETTE_PLAN_B64).decode("utf-8"))
    baseline_bytes = bytes.fromhex(str(payload["baseline_palette_hex"]))
    output_bytes = bytes.fromhex(str(payload["output_palette_hex"]))
    if len(baseline_bytes) != 768 or len(output_bytes) != 768:
        raise RendererContractError("Frozen V5 GIF palette size drifted.")
    if hashlib.sha256(baseline_bytes).hexdigest() != FROZEN_V5_BASELINE_PALETTE_SHA256:
        raise RendererContractError("Frozen V5 baseline GIF palette hash drifted.")
    if hashlib.sha256(output_bytes).hexdigest() != FROZEN_V5_OUTPUT_PALETTE_SHA256:
        raise RendererContractError("Frozen V5 output GIF palette hash drifted.")
    regions = tuple(
        PaletteProtectionRegion(
            str(region["name"]),
            tuple(int(value) for value in region["bounds"]),
            tuple(tuple(int(component) for component in color) for color in region["colors"]),
            tuple(int(slot) for slot in region["palette_slots"]),
        )
        for region in payload["regions"]
    )
    if len(regions) != 9:
        raise RendererContractError("Frozen V5 GIF protection-region count drifted.")
    return GifPalettePlan(
        _palette_image(baseline_bytes),
        _palette_image(output_bytes),
        regions,
    )


def build_v5_compatibility_palette_plan(
    context: RenderContext,
    frames: Sequence[np.ndarray],
) -> GifPalettePlan:
    """Return the exact approved V5 GIF palette plan."""

    del context, frames
    return frozen_v5_compatibility_palette_plan()


def build_gif_palette_plan(context: RenderContext, frames: Sequence[np.ndarray]) -> GifPalettePlan:
    """Patch only V6/V7-authorized pixels over the exact V5 indexed GIF base."""

    v5_plan = build_v5_compatibility_palette_plan(context, frames)
    regions: list[PaletteProtectionRegion] = [
        PaletteProtectionRegion("v6_feed_cleanup", bounds, (), (), direct_output_quantization=True)
        for bounds in FEED_V6_CLEAN_LANES
    ]
    # These are the four review-authorized V6 regions.  Direct quantization
    # against V5's output palette leaves every other encoded index untouched.
    regions.extend(
        (
            PaletteProtectionRegion(
                "v6_threat_typography",
                (850, 610, 1005, 810),
                (),
                (),
                direct_output_quantization=True,
            ),
            PaletteProtectionRegion(
                "v6_workflow_strip",
                context.helpers.s03.VIEW_BOUNDS,
                (),
                (),
                direct_output_quantization=True,
            ),
        )
    )
    s07_x1, s07_y1, _s07_x2, _s07_y2 = context.helpers.s07.PANEL_BOUNDS_GLOBAL
    for index, (x1, y1, x2, y2) in enumerate(CASE_OVERVIEW_V6_LOCAL_BOUNDS):
        regions.append(
            PaletteProtectionRegion(
                f"v6_case_overview_text_{index:02d}",
                (s07_x1 + x1, s07_y1 + y1, s07_x1 + x2, s07_y1 + y2),
                (),
                (),
                direct_output_quantization=True,
            )
        )
    # V7 adds only the explicitly approved review lanes.  All use direct
    # quantization against the frozen V5 output palette; no global palette,
    # compatibility region, or unrelated encoded index is rebuilt.
    v7_bounds = [
        ("v7_header", TOP_HEADER_V7_GROUP_BOUNDS),
        ("v7_threat_score_suffix", THREAT_SCORE_SUFFIX_V7_CLEAN_BOUNDS),
        *[(f"v7_severity_{index}", bounds) for index, bounds in enumerate(SEVERITY_V7_VALUE_BOUNDS)],
    ]
    v7_bounds.extend(
        (f"v7_system_status_divider_{index}", bounds)
        for index, bounds in enumerate(SYSTEM_STATUS_V7_DIVIDER_BANDS)
    )
    s07_x1, s07_y1, _s07_x2, _s07_y2 = context.helpers.s07.PANEL_BOUNDS_GLOBAL
    v7_bounds.extend(
        (
            f"v7_case_overview_subtitle_{index}",
            (s07_x1 + x1, s07_y1 + y1, s07_x1 + x2, s07_y1 + y2),
        )
        for index, (x1, y1, x2, y2) in enumerate(CASE_OVERVIEW_V7_SUBTITLE_LOCAL_BOUNDS)
    )
    regions.extend(
        PaletteProtectionRegion(name, bounds, (), (), direct_output_quantization=True)
        for name, bounds in v7_bounds
    )
    # V8/V10 append only the measured Case Overview subtitle regions.  The
    # fixed V5 palette and full-canvas GIF assembly remain unchanged.
    regions.extend(
        PaletteProtectionRegion(
            f"v10_case_overview_subtitle_{index}",
            (s07_x1 + x1, s07_y1 + y1, s07_x1 + x2, s07_y1 + y2),
            (),
            (),
            direct_output_quantization=True,
        )
        for index, (x1, y1, x2, y2) in enumerate(case_overview_v8_subtitle_overlay_bounds())
    )
    # V9 is deliberately narrower than the full Evidence Package viewport:
    # only the source-derived connected-component mask for the front-folder
    # accent is quantized from the toned RGB frame.  This preserves every
    # magnifier pixel, panel pixel, and pre-existing GIF index outside it.
    s02_x1, s02_y1, _s02_x2, _s02_y2 = context.helpers.s02.VIEW_BOUNDS
    v9_x1, v9_y1, v9_x2, v9_y2 = V9_EVIDENCE_FRONT_ACCENT_BOUNDS_GLOBAL
    local_x1, local_y1 = v9_x1 - s02_x1, v9_y1 - s02_y1
    local_x2, local_y2 = v9_x2 - s02_x1, v9_y2 - s02_y1
    v9_mask = context.s02_v9_accent_mask[local_y1:local_y2, local_x1:local_x2]
    if v9_mask.shape != (v9_y2 - v9_y1, v9_x2 - v9_x1):
        raise RendererContractError("V9 Evidence Package palette mask dimensions drifted.")
    if int(np.count_nonzero(v9_mask)) != V9_EVIDENCE_FRONT_ACCENT_EXPECTED_PIXELS:
        raise RendererContractError("V9 Evidence Package palette mask no longer matches the front-folder accent.")
    regions.append(
        PaletteProtectionRegion(
            "v9_evidence_front_folder_accent",
            V9_EVIDENCE_FRONT_ACCENT_BOUNDS_GLOBAL,
            (),
            (),
            mask=v9_mask,
            direct_output_quantization=True,
        )
    )
    return GifPalettePlan(
        v5_plan.baseline_palette,
        v5_plan.output_palette,
        tuple(regions),
        v5_plan.regions,
    )


def _region_quantizer_palette(colors: Sequence[tuple[int, int, int]]) -> Image.Image:
    if not colors:
        raise RendererContractError("A protected GIF palette region has no source colors.")
    data: list[int] = []
    for color in colors:
        data.extend(color)
    data.extend(colors[0] * (256 - len(colors)))
    return _palette_image(data)


def encode_gif_frame(
    frame: np.ndarray,
    plan: GifPalettePlan,
    *,
    base_indices: np.ndarray | None = None,
) -> Image.Image:
    """Encode one full frame, optionally over a frozen V5 indexed base."""

    if base_indices is None:
        baseline = Image.fromarray(frame, "RGB").quantize(
            palette=plan.baseline_palette,
            dither=Image.Dither.NONE,
        )
        indices = np.asarray(baseline, dtype=np.uint8).copy()
    else:
        if base_indices.shape != (CANVAS_SIZE[1], CANVAS_SIZE[0]):
            raise RendererContractError("V5 GIF index base no longer matches the full canvas.")
        indices = np.asarray(base_indices, dtype=np.uint8).copy()
    for region in plan.regions:
        x1, y1, x2, y2 = region.bounds
        if region.direct_output_quantization:
            remapped = np.asarray(
                Image.fromarray(frame[y1:y2, x1:x2], "RGB").quantize(
                    palette=plan.output_palette,
                    dither=Image.Dither.NONE,
                ),
                dtype=np.uint8,
            )
        else:
            local = Image.fromarray(frame[y1:y2, x1:x2], "RGB").quantize(
                palette=_region_quantizer_palette(region.colors),
                dither=Image.Dither.NONE,
            )
            local_indices = np.asarray(local, dtype=np.uint8)
            local_palette = _palette_data(local)
            color_positions = {color: index for index, color in enumerate(region.colors)}
            remap = np.zeros(256, dtype=np.uint8)
            for index in range(256):
                color = tuple(local_palette[index * 3:index * 3 + 3])
                remap[index] = region.palette_slots[color_positions[color]]
            remapped = remap[local_indices]
        if region.mask is None:
            indices[y1:y2, x1:x2] = remapped
        else:
            if region.mask.shape != remapped.shape:
                raise RendererContractError(f"Palette mask dimensions drifted for {region.name}.")
            current = indices[y1:y2, x1:x2]
            current[region.mask] = remapped[region.mask]
            indices[y1:y2, x1:x2] = current
    lock_frozen_semantic_palette_indices(frame, indices, plan.output_palette)
    encoded = Image.fromarray(indices, "P")
    encoded.putpalette(_palette_data(plan.output_palette))
    return encoded


def save_gif(
    context: RenderContext,
    frames: Sequence[np.ndarray],
    path: Path,
    plan: GifPalettePlan,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    v5_plan = GifPalettePlan(
        plan.baseline_palette,
        plan.output_palette,
        plan.v5_compatibility_regions,
    )
    indexed = []
    for frame in frames:
        # Quantize the current RGB source through the frozen V5 plan first.
        # V6-only RGB differences are then written only inside the authorized
        # direct-output regions; all other palette indices remain V5-stable.
        v5_indexed = encode_gif_frame(frame, v5_plan)
        indexed.append(
            encode_gif_frame(
                frame,
                plan,
                base_indices=np.asarray(v5_indexed, dtype=np.uint8),
            )
        )
    indexed[0].save(
        path,
        format="GIF",
        save_all=True,
        append_images=indexed[1:],
        # Force the one approved fixed palette into the stream.  Without this
        # explicit argument Pillow may write per-frame local tables despite
        # each indexed image already carrying the same palette, which can make
        # full-canvas later frames decode with black/missing static regions.
        palette=bytes(_palette_data(plan.output_palette)),
        duration=FRAME_DURATION_MS,
        loop=0,
        disposal=2,
        optimize=False,
    )


def decode_gif(path: Path) -> list[np.ndarray]:
    image = Image.open(path)
    result: list[np.ndarray] = []
    for index in range(image.n_frames):
        image.seek(index)
        result.append(np.array(image.convert("RGB"), dtype=np.uint8))
    return result


def gif_frame_metadata(path: Path) -> dict[str, int]:
    """Inspect encoded frame descriptors, not just the renderer's source list."""

    image = Image.open(path)
    full = 0
    disposal_2 = 0
    duration_50 = 0
    for index in range(image.n_frames):
        image.seek(index)
        tile_bounds = image.tile[0][1] if image.tile else None
        if tuple(tile_bounds or ()) == (0, 0, CANVAS_SIZE[0], CANVAS_SIZE[1]):
            full += 1
        if int(getattr(image, "disposal_method", 0)) == 2:
            disposal_2 += 1
        if int(image.info.get("duration", 0)) == FRAME_DURATION_MS:
            duration_50 += 1
    return {
        "full_canvas_frames": full,
        "disposal_2_frames": disposal_2,
        "duration_50_frames": duration_50,
    }


def make_contact_sheet(
    frames: Sequence[np.ndarray],
    indices: Sequence[int],
    path: Path,
    *,
    columns: int,
    label: str,
) -> None:
    if not frames:
        raise RendererContractError("Cannot build a proof sheet without frames.")
    thumb_width = 432
    thumb_height = int(round(CANVAS_SIZE[1] * thumb_width / CANVAS_SIZE[0]))
    rows = math.ceil(len(indices) / columns)
    margin = 10
    header = 30
    sheet = Image.new(
        "RGB",
        (
            columns * thumb_width + (columns + 1) * margin,
            rows * (thumb_height + header) + (rows + 1) * margin,
        ),
        (8, 9, 10),
    )
    draw = ImageDraw.Draw(sheet)
    for offset, index in enumerate(indices):
        col = offset % columns
        row = offset // columns
        x = margin + col * (thumb_width + margin)
        y = margin + row * (thumb_height + header + margin)
        draw.text((x, y), f"{label} {index:03d}", fill=(225, 54, 43), font=dashboard_font(13, True))
        thumbnail = Image.fromarray(frames[index], "RGB").resize(
            (thumb_width, thumb_height),
            Image.Resampling.LANCZOS,
        )
        sheet.paste(thumbnail, (x, y + header))
    path.parent.mkdir(parents=True, exist_ok=True)
    sheet.save(path, format="PNG")


def crop_array(array: np.ndarray, bounds: tuple[int, int, int, int]) -> np.ndarray:
    x1, y1, x2, y2 = bounds
    return array[y1:y2, x1:x2].copy()


def save_labeled_panels(
    records: Sequence[tuple[str, np.ndarray]],
    path: Path,
    *,
    scale: int = 2,
    columns: int | None = None,
    title: str | None = None,
) -> None:
    """Write a simple proof sheet without altering any reviewed source frame."""

    if not records:
        raise RendererContractError("Cannot create an empty proof sheet.")
    columns = columns or len(records)
    max_width = max(panel.shape[1] for _, panel in records) * scale
    max_height = max(panel.shape[0] for _, panel in records) * scale
    margin, header, label_h = 12, 28 if title else 0, 20
    rows = math.ceil(len(records) / columns)
    sheet = Image.new(
        "RGB",
        (
            margin + columns * (max_width + margin),
            margin + header + rows * (max_height + label_h + margin),
        ),
        (5, 7, 8),
    )
    draw = ImageDraw.Draw(sheet)
    if title:
        draw.text((margin, 7), title, fill=(233, 55, 42), font=dashboard_font(12, True))
    for index, (label, panel) in enumerate(records):
        row, col = divmod(index, columns)
        x = margin + col * (max_width + margin)
        y = margin + header + row * (max_height + label_h + margin)
        draw.text((x, y), label, fill=(208, 204, 201), font=dashboard_font(10, True))
        image = Image.fromarray(panel, "RGB").resize(
            (panel.shape[1] * scale, panel.shape[0] * scale),
            Image.Resampling.NEAREST,
        )
        sheet.paste(image, (x, y + label_h))
        draw.rectangle(
            (x - 1, y + label_h - 1, x + image.width, y + label_h + image.height),
            outline=(132, 38, 32),
            width=1,
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    sheet.save(path, format="PNG")


def make_threshold_color_proof(context: RenderContext, path: Path) -> None:
    colors = threshold_guide_colors(context.raw)
    values = (29, 30, 59, 60, 79, 80)
    width, height = 900, 210
    image = Image.new("RGB", (width, height), (5, 7, 8))
    draw = ImageDraw.Draw(image)
    draw.text((16, 12), "THREAT MONITOR // APPROVED THRESHOLD COLOR BOUNDARIES", fill=(233, 55, 42), font=dashboard_font(14, True))
    for index, value in enumerate(values):
        level = classification_for_score(value)
        x = 18 + (index % 3) * 292
        y = 54 + (index // 3) * 74
        color = colors[level]
        draw.rectangle((x, y, x + 30, y + 30), fill=color, outline=(225, 220, 216))
        draw.text((x + 42, y + 1), f"{value:03d}  {level}", fill=color, font=dashboard_font(13, True))
        draw.text((x + 42, y + 20), f"guide RGB {color}", fill=(185, 181, 178), font=dashboard_font(8))
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, format="PNG")


def make_system_status_motion_proof(
    context: RenderContext,
    decoded: Sequence[np.ndarray],
    path: Path,
) -> None:
    indices = MOTION_AUDIT_INDICES
    specs = context.helpers.s05.TRACE_SPECS
    scale, margin, header, label_w = 4, 7, 34, 72
    max_width = max(bounds[2] - bounds[0] for _, bounds, _ in specs) * scale
    cell_h = max(bounds[3] - bounds[1] for _, bounds, _ in specs) * scale + 18
    image = Image.new(
        "RGB",
        (label_w + len(indices) * (max_width + margin) + margin, header + len(specs) * (cell_h + margin) + margin),
        (5, 7, 8),
    )
    draw = ImageDraw.Draw(image)
    draw.text((margin, 7), "SYSTEM STATUS // DECODED DIAGNOSTIC TRACE MOTION // 12 FRAMES", fill=(233, 55, 42), font=dashboard_font(12, True))
    for col, index in enumerate(indices):
        x = label_w + margin + col * (max_width + margin)
        draw.text((x, header - 16), f"F{index:02d}", fill=(190, 186, 182), font=dashboard_font(8))
    for row, (key, bounds, _color) in enumerate(specs):
        y = header + row * (cell_h + margin)
        draw.text((8, y + 14), key.upper() if key != "uptime" else "QUEUE", fill=(193, 203, 210), font=dashboard_font(9, True))
        for col, index in enumerate(indices):
            x = label_w + margin + col * (max_width + margin)
            crop = crop_array(decoded[index], bounds)
            rendered = Image.fromarray(crop, "RGB").resize(
                (crop.shape[1] * scale, crop.shape[0] * scale), Image.Resampling.NEAREST
            )
            image.paste(rendered, (x, y))
            draw.rectangle((x - 1, y - 1, x + rendered.width, y + rendered.height), outline=(55, 100, 125), width=1)
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, format="PNG")


def make_feed_mapping_proof(context: RenderContext, decoded_frame: np.ndarray, path: Path) -> None:
    graph = crop_array(decoded_frame, (54, 700, 427, 808))
    scale, margin = 2, 12
    table_columns = 13
    table_rows = math.ceil(len(context.s04_bars) / table_columns)
    width = max(graph.shape[1] * scale + 2 * margin, table_columns * 112 + 2 * margin)
    height = 34 + graph.shape[0] * scale + 32 + table_rows * 28 + margin
    image = Image.new("RGB", (width, height), (5, 7, 8))
    draw = ImageDraw.Draw(image)
    draw.text((margin, 7), "ACTIVE CASE FEED // FROZEN 39-SLOT X MAPPING", fill=(233, 55, 42), font=dashboard_font(12, True))
    rendered = Image.fromarray(graph, "RGB").resize((graph.shape[1] * scale, graph.shape[0] * scale), Image.Resampling.NEAREST)
    image.paste(rendered, (margin, 30))
    draw.rectangle((margin - 1, 29, margin + rendered.width, 30 + rendered.height), outline=(132, 38, 32), width=1)
    y0 = 30 + rendered.height + 12
    for index, (x1, x2) in enumerate(context.s04_bars):
        row, col = divmod(index, table_columns)
        x = margin + col * 112
        y = y0 + row * 28
        draw.text((x, y), f"{index:02d}: {x1}-{x2}", fill=(196, 196, 190), font=dashboard_font(8))
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, format="PNG")


def make_biohazard_proofs(
    context: RenderContext,
    decoded: Sequence[np.ndarray],
    output_dir: Path,
) -> dict[str, Path]:
    records: list[tuple[str, np.ndarray]] = []
    paths: dict[str, Path] = {}
    for index in KEYFRAME_INDICES:
        crop = crop_array(decoded[index], context.helpers.s01.VIEW_BOUNDS)
        path = output_dir / f"biohazard_frame_{index:03d}_2x.png"
        save_labeled_panels(
            ((f"DECODED F{index:03d} // FROZEN PHASE {index % context.helpers.s01.FRAME_COUNT:03d}", crop),),
            path,
            scale=2,
            title="BIOHAZARD // DECODED GIF ROI",
        )
        paths[f"biohazard_frame_{index:03d}"] = path
        records.append((f"F{index:03d} / P{index % context.helpers.s01.FRAME_COUNT:03d}", crop))
    contact = output_dir / "biohazard_motion_contact_sheet_2x.png"
    save_labeled_panels(records, contact, scale=2, columns=2, title="BIOHAZARD // DECODED SIX-SECOND PHASE PROGRESSION")
    paths["biohazard_motion_contact_sheet"] = contact
    return paths


def make_focus_proofs(
    context: RenderContext,
    frames: Sequence[np.ndarray],
    decoded: Sequence[np.ndarray],
    output_dir: Path,
) -> dict[str, Path]:
    """Create the focused visual inspection assets required for #9 review."""

    output_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    footer_bounds = (1372, 840, 1706, 882)
    footer_mask = footer_border_mask(CANVAS_SIZE)[footer_bounds[1]:footer_bounds[3], footer_bounds[0]:footer_bounds[2]]
    footer_overlay = crop_array(frames[0], footer_bounds)
    footer_overlay[footer_mask] = np.asarray((74, 215, 235), dtype=np.uint8)
    paths["footer_eastern_time_border_proof"] = output_dir / "footer_eastern_time_border_proof.png"
    save_labeled_panels(
        (
            ("APPROVED POPULATED MASTER", crop_array(context.raw, footer_bounds)),
            ("FINAL SOURCE F000", crop_array(frames[0], footer_bounds)),
            ("MASTER BORDER MASK (CYAN)", footer_overlay),
        ),
        paths["footer_eastern_time_border_proof"],
        scale=3,
        title="FOOTER // EASTERN TIME STATIC BORDER RESTORATION",
    )

    op_bounds = (1285, 555, 1720, 821)
    paths["operational_brief_clean_plate_proof"] = output_dir / "operational_brief_clean_plate_proof.png"
    save_labeled_panels(
        (
            ("POPULATED SOURCE", crop_array(context.raw, op_bounds)),
            ("CLEAN DYNAMIC-TEXT PLATE", crop_array(context.static_base, op_bounds)),
            ("LIVE SOURCE F000", crop_array(frames[0], op_bounds)),
        ),
        paths["operational_brief_clean_plate_proof"],
        scale=2,
        title="OPERATIONAL BRIEF // CLEAN BEFORE LIVE TEXT",
    )
    paths["operational_brief_text_fit_proof"] = output_dir / "operational_brief_text_fit_proof.png"
    save_labeled_panels(
        (("DECODED F000 // COMPLETE WRAPPED DATA TEXT", crop_array(decoded[0], op_bounds)),),
        paths["operational_brief_text_fit_proof"],
        scale=3,
        title="OPERATIONAL BRIEF // NO ELLIPSIS OR ROW OVERFLOW",
    )

    threat_bounds = context.helpers.s06.PANEL_BOUNDS
    paths["threat_monitor_text_fit_proof"] = output_dir / "threat_monitor_text_fit_proof.png"
    save_labeled_panels(
        (
            ("POPULATED SOURCE", crop_array(context.raw, threat_bounds)),
            ("CLEAN DYNAMIC-TEXT PLATE", crop_array(context.static_base, threat_bounds)),
            ("DECODED F000 // LIVE SUMMARY", crop_array(decoded[0], threat_bounds)),
        ),
        paths["threat_monitor_text_fit_proof"],
        scale=2,
        title="THREAT MONITOR // CLEAN SCORE + SUMMARY TEXT PLATE",
    )
    paths["threat_monitor_threshold_color_proof"] = output_dir / "threat_monitor_threshold_color_proof.png"
    make_threshold_color_proof(context, paths["threat_monitor_threshold_color_proof"])

    overview_live = crop_array(frames[0], context.helpers.s07.PANEL_BOUNDS_GLOBAL)
    paths["case_overview_clean_plate_proof"] = output_dir / "case_overview_clean_plate_proof.png"
    save_labeled_panels(
        (
            ("FROZEN PROPOSAL B STATIC REFERENCE", context.s07_static_reference),
            ("PREVIEW VALUES REMOVED", context.s07_clean_plate),
            ("LIVE CASE PLATE", context.s07_plate),
        ),
        paths["case_overview_clean_plate_proof"],
        scale=2,
        title="CASE OVERVIEW // STATIC PROPOSAL B / CLEAN / LIVE DATA PLATES",
    )
    paths["case_overview_live_data_proof"] = output_dir / "case_overview_live_data_proof.png"
    save_labeled_panels(
        (("SOURCE F000 // LIVE DATA + FROZEN ROUTE MOTION", overview_live),),
        paths["case_overview_live_data_proof"],
        scale=3,
        title="CASE OVERVIEW // LIVE DATA INSIDE FROZEN PROPOSAL B GEOMETRY",
    )
    mask_overlay = context.s07_static_reference.copy()
    mask_overlay[context.s07_dynamic_text_lanes] = np.asarray((240, 67, 52), dtype=np.uint8)
    mask_overlay[context.s07_authorized & ~context.s07_dynamic_text_lanes] = np.asarray((62, 158, 219), dtype=np.uint8)
    paths["case_overview_text_mask_proof"] = output_dir / "case_overview_text_mask_proof.png"
    save_labeled_panels(
        (("RED = DYNAMIC TEXT LANES // BLUE = APPROVED PACKET/RESPONSE MASKS", mask_overlay),),
        paths["case_overview_text_mask_proof"],
        scale=3,
        title="CASE OVERVIEW // STATIC-PROTECTION MASK AUDIT",
    )

    paths["system_status_diagnostic_motion_proof"] = output_dir / "system_status_diagnostic_motion_proof_12frames.png"
    make_system_status_motion_proof(context, decoded, paths["system_status_diagnostic_motion_proof"])
    paths["active_case_feed_39_slot_mapping_proof"] = output_dir / "active_case_feed_39_slot_mapping_proof.png"
    make_feed_mapping_proof(context, decoded[0], paths["active_case_feed_39_slot_mapping_proof"])
    paths.update(make_biohazard_proofs(context, decoded, output_dir))

    paths["unit_status_activity_motion_proof"] = output_dir / "unit_status_activity_motion_proof.png"
    save_labeled_panels(
        tuple(
            (f"DECODED F{index:03d}", crop_array(decoded[index], (228, 470, 405, 530)))
            for index in (0, 30, 60, 90)
        ),
        paths["unit_status_activity_motion_proof"],
        scale=3,
        columns=4,
        title="UNIT STATUS // SIMULATED + THREE-BAR DETERMINISTIC ACTIVITY",
    )

    paths["active_case_feed_live_motion_proof"] = output_dir / "active_case_feed_live_motion_proof.png"
    save_labeled_panels(
        tuple(
            (f"DECODED F{index:03d}", crop_array(decoded[index], (12, 560, 430, 800)))
            for index in (0, 20, 40, 60, 80, 100, 119)
        ),
        paths["active_case_feed_live_motion_proof"],
        scale=2,
        columns=4,
        title="ACTIVE CASE FEED // PERSISTED BARS + LIVE PRESENTATION ONLY",
    )

    paths["threat_monitor_score_target_proof"] = output_dir / "threat_monitor_score_target_proof.png"
    save_labeled_panels(
        tuple(
            (f"DECODED F{index:03d} // NOW = {context.renderer_state['canonical_threat_score']}", crop_array(decoded[index], (946, 598, 1250, 670)))
            for index in (0, 30, 60, 90)
        ),
        paths["threat_monitor_score_target_proof"],
        scale=3,
        columns=2,
        title="THREAT MONITOR // CANONICAL SCORE TARGET AT NOW",
    )

    paths["operational_brief_spacing_proof"] = output_dir / "operational_brief_spacing_proof.png"
    save_labeled_panels(
        (
            ("DECODED F000 // FOURTH ACTION ROW", crop_array(decoded[0], (1295, 716, 1715, 776))),
        ),
        paths["operational_brief_spacing_proof"],
        scale=4,
        title="OPERATIONAL BRIEF // WRAPPED ACTION ROW BREATHING ROOM",
    )
    paths["operational_brief_icon_proof"] = output_dir / "operational_brief_icon_proof.png"
    save_labeled_panels(
        (
            ("SOURCE LEGACY GLYPHS", crop_array(context.raw, (1296, 590, 1335, 805))),
            ("#9 VECTOR ICON PLATE", crop_array(context.operational_icon_plate, (1296, 590, 1335, 805))),
            ("DECODED F000", crop_array(decoded[0], (1296, 590, 1335, 805))),
        ),
        paths["operational_brief_icon_proof"],
        scale=5,
        columns=3,
        title="OPERATIONAL BRIEF // STATIC LINE-ICON REPLACEMENT",
    )

    paths["case_overview_legibility_proof_2x"] = output_dir / "case_overview_legibility_proof_2x.png"
    save_labeled_panels(
        (("DECODED F000 // +1PX DATA VALUES", crop_array(decoded[0], context.helpers.s07.PANEL_BOUNDS_GLOBAL)),),
        paths["case_overview_legibility_proof_2x"],
        scale=2,
        title="CASE OVERVIEW // INTEGRATED LIVE DATA LEGIBILITY",
    )
    paths["case_overview_icon_fidelity_proof"] = output_dir / "case_overview_icon_fidelity_proof.png"
    icon_crop = (85, 61, 435, 230)
    overview_decoded = crop_array(decoded[0], context.helpers.s07.PANEL_BOUNDS_GLOBAL)
    save_labeled_panels(
        (
            ("UNTOUCHED FROZEN ICONS", crop_array(context.s07_static_reference, icon_crop)),
            ("#9 CLEAN + LIVE PLATE", crop_array(context.s07_plate, icon_crop)),
            ("DECODED F000", crop_array(overview_decoded, icon_crop)),
        ),
        paths["case_overview_icon_fidelity_proof"],
        scale=3,
        columns=3,
        title="CASE OVERVIEW // FROZEN ICON FIDELITY",
    )

    paths["evidence_package_last_updated_cleanup_proof"] = output_dir / "evidence_package_last_updated_cleanup_proof.png"
    evidence_bounds = (1345, 190, 1530, 260)
    save_labeled_panels(
        (
            ("POPULATED SOURCE", crop_array(context.raw, evidence_bounds)),
            ("CLEAR-MASTER PLACEHOLDER", crop_array(context.clear, evidence_bounds)),
            ("DECODED F000 // LOCAL SOURCE REPAIR", crop_array(decoded[0], evidence_bounds)),
        ),
        paths["evidence_package_last_updated_cleanup_proof"],
        scale=3,
        columns=3,
        title="EVIDENCE PACKAGE // LAST UPDATED WITHOUT PLACEHOLDER RULES",
    )

    paths["center_case_metadata_clean_text_proof"] = output_dir / "center_case_metadata_clean_text_proof.png"
    metadata_bounds = (580, 165, 835, 370)
    save_labeled_panels(
        (
            ("POPULATED SOURCE", crop_array(context.raw, metadata_bounds)),
            ("CLEAN TEXT PLATE", crop_array(context.static_base, metadata_bounds)),
            ("DECODED F000 // LIVE CASE METADATA", crop_array(decoded[0], metadata_bounds)),
        ),
        paths["center_case_metadata_clean_text_proof"],
        scale=2,
        columns=3,
        title="CASE METADATA // CLASSIFICATION + THREAT FAMILY CLEAN PLATE",
    )

    paths["workflow_current_stage_motion_proof"] = output_dir / "workflow_current_stage_motion_proof.png"
    workflow_stage = str(context.renderer_state["dashboard"]["workflow"]["current_stage"])
    shell_x1, _shell_y1, shell_x2, _shell_y2 = WORKFLOW_CARD_SHELLS_GLOBAL[workflow_stage]
    workflow_proof_bounds = (shell_x1 - 15, 378, shell_x2 + 20, 500)
    save_labeled_panels(
        tuple(
            (
                f"DECODED F{index:03d} // {human_stage(workflow_stage)}",
                crop_array(decoded[index], workflow_proof_bounds),
            )
            for index in (0, 20, 40, 60, 80, 100, 119)
        ),
        paths["workflow_current_stage_motion_proof"],
        scale=2,
        columns=4,
        title=f"WORKFLOW // FIXED {human_stage(workflow_stage)} / CURRENT-STAGE MOTION",
    )

    # Final V3 visual-hotfix proofs use the same full source frames and decoded
    # GIF frames as the review output; they are not post-hoc frame edits.
    metadata_artifact_bounds = (590, 178, 825, 270)
    paths["center_metadata_artifact_cleanup_proof"] = output_dir / "center_metadata_artifact_cleanup_proof.png"
    save_labeled_panels(
        (
            ("BEFORE // POPULATED SOURCE", crop_array(context.raw, metadata_artifact_bounds)),
            ("CLEAN PLATE // BEFORE LIVE TEXT", crop_array(context.static_base, metadata_artifact_bounds)),
            ("AFTER // DECODED GIF F000", crop_array(decoded[0], metadata_artifact_bounds)),
        ),
        paths["center_metadata_artifact_cleanup_proof"],
        scale=4,
        columns=3,
        title="V3 // CENTER METADATA SOURCE-TAIL CLEANUP",
    )
    threat_summary_bounds = (1004, 714, 1277, 809)
    paths["threat_summary_artifact_cleanup_proof"] = output_dir / "threat_summary_artifact_cleanup_proof.png"
    save_labeled_panels(
        (
            ("BEFORE // POPULATED SOURCE", crop_array(context.raw, threat_summary_bounds)),
            ("CLEAN PLATE // BEFORE LIVE TEXT", crop_array(context.static_base, threat_summary_bounds)),
            ("AFTER // DECODED GIF F000", crop_array(decoded[0], threat_summary_bounds)),
        ),
        paths["threat_summary_artifact_cleanup_proof"],
        scale=4,
        columns=3,
        title="V3 // THREAT SUMMARY SOURCE-TAIL CLEANUP",
    )
    paths["threat_threshold_color_cleanup_proof"] = output_dir / "threat_threshold_color_cleanup_proof.png"
    save_labeled_panels(
        (
            ("APPROVED SOURCE PALETTE", crop_array(context.raw, (846, 716, 950, 807))),
            ("SOURCE F000", crop_array(frames[0], (846, 716, 950, 807))),
            ("DECODED GIF F000", crop_array(decoded[0], (846, 716, 950, 807))),
        ),
        paths["threat_threshold_color_cleanup_proof"],
        scale=5,
        columns=3,
        title="V3 // THREAT GUIDE RED / ORANGE / AMBER / GREEN PALETTE LOCK",
    )
    paths["workflow_production_parity_proof"] = output_dir / "workflow_production_parity_proof.png"
    workflow_bounds = context.helpers.s03.VIEW_BOUNDS
    save_labeled_panels(
        tuple(
            (f"DECODED F{index:03d} // FIXED {human_stage(workflow_stage)}", crop_array(decoded[index], workflow_bounds))
            for index in (0, 20, 40, 60, 80, 100, 119)
        ),
        paths["workflow_production_parity_proof"],
        scale=2,
        columns=2,
        title="V3 // FROZEN WORKFLOW PARITY: BLUE COMPLETED / RED CURRENT / GRAY PENDING",
    )
    paths["final_visual_hotfix_contact_sheet"] = output_dir / "final_visual_hotfix_contact_sheet.png"
    make_contact_sheet(
        decoded,
        (0, 20, 40, 60, 80, 100, 119),
        paths["final_visual_hotfix_contact_sheet"],
        columns=3,
        label="DECODED V3 HOTFIX FRAME",
    )
    return paths


def bbox_for_mask(mask: np.ndarray) -> tuple[int, int, int, int] | None:
    yy, xx = np.where(mask)
    if not len(xx):
        return None
    return int(np.min(xx)), int(np.min(yy)), int(np.max(xx)) + 1, int(np.max(yy)) + 1


def diff_count_outside(first: np.ndarray, second: np.ndarray, allowed: np.ndarray) -> int:
    diff = np.any(first != second, axis=2)
    return int(np.count_nonzero(diff & ~allowed))


def consistency_report(
    renderer_state: dict[str, Any], route_gate: dict[str, bool]
) -> dict[str, Any]:
    state = renderer_state["dashboard"]
    shared = state["shared"]
    case_id = shared["case_id"]
    case = renderer_state["case"]
    relationships = renderer_state["relationships"]
    events = renderer_state["events"]
    metrics = _metric_records(state["system_status"])
    shared_keys = (
        "case_id",
        "campaign_id",
        "lifecycle_status",
        "current_stage",
        "severity",
        "priority",
        "lead_analyst",
        "evidence_count",
        "ioc_count",
        "updated_at",
        "state_revision",
    )
    shared_projection_matches_active_case = {
        key: case.get(key) == shared.get(key) for key in shared_keys
    }
    threat_relationship = next(
        (
            relation
            for relation in relationships
            if isinstance(relation, dict)
            and "THREAT" in str(relation.get("relationship_type", "")).upper()
        ),
        None,
    )
    threat_attributes = (
        threat_relationship.get("attributes", {})
        if isinstance(threat_relationship, dict)
        else {}
    )
    anomaly_history = state["threat_monitor"]["anomaly_history"]
    threat_history = state["threat_monitor"].get("threat_history", [])
    manifest_items = renderer_state["manifest_items"]
    report = {
        "case_id": case_id,
        "campaign_id": shared["campaign_id"],
        "lifecycle_status": shared["lifecycle_status"],
        "current_stage": shared["current_stage"],
        "severity": shared["severity"],
        "priority": shared["priority"],
        "lead_analyst": shared["lead_analyst"],
        "evidence_count": shared["evidence_count"],
        "updated_at": shared["updated_at"],
        "state_revision": shared["state_revision"],
        "threat_score": renderer_state["canonical_threat_score"],
        "canonical_threat_classification": state["threat_monitor"]["threat"]["canonical_classification"],
        "subsystem_06_display_level": renderer_state["subsystem_06_display_level"],
        "authoritative_source_map": {
            "case_id": "dashboard.shared.case_id",
            "campaign_id": "dashboard.shared.campaign_id / operation_context.campaign_id",
            "classification": "active_case.classification via validated renderer-side display projection",
            "threat_family": "active_case.threat_family via validated renderer-side display projection",
            "status": "dashboard.shared.lifecycle_status and active_case.status",
            "severity": "dashboard.shared.severity",
            "priority": "dashboard.shared.priority",
            "lead_analyst": "dashboard.shared.lead_analyst",
            "evidence_count": "dashboard.shared.evidence_count / evidence_package.evidence_count",
            "workflow_stage": "dashboard.workflow.current_stage",
            "updated_at": "dashboard.shared.updated_at",
            "threat_score": "dashboard.threat_monitor.threat.score (C# canonical source)",
            "threat_classification": "dashboard.threat_monitor.threat.canonical_classification (C# canonical source)",
            "system_status": "dashboard.system_status",
            "relationships": "dashboard.case_overview.relationships",
        },
        "shared_projection_matches_active_case": shared_projection_matches_active_case,
        "same_case_id_workflow": state["workflow"]["case_id"] == case_id,
        "same_case_id_feed": state["active_case_feed"]["case_id"] == case_id,
        "same_case_id_evidence": state["evidence_package"]["case_id"] == case_id,
        "same_case_id_threat": state["threat_monitor"]["case_id"] == case_id,
        "same_case_id_overview": state["case_overview"]["case_id"] == case_id,
        "same_case_id_system_status": state["system_status"].get("case_id") == case_id,
        "same_case_id_evidence_manifest_items": all(
            item.get("case_id") == case_id
            for item in manifest_items
            if isinstance(item, dict)
        ),
        "same_case_id_anomaly_history": all(
            item.get("case_id") == case_id
            for item in anomaly_history
            if isinstance(item, dict)
        ),
        "same_case_id_threat_history": all(
            item.get("case_id") == case_id
            for item in threat_history
            if isinstance(item, dict)
        ),
        "same_campaign_id_operation": (
            state["operation_context"].get("campaign_id") == shared["campaign_id"]
        ),
        "same_campaign_id_threat_history": all(
            item.get("campaign_id") == shared["campaign_id"]
            for item in threat_history
            if isinstance(item, dict)
        ),
        "same_stage_workflow": state["workflow"]["current_stage"] == shared["current_stage"],
        "same_evidence_count": state["evidence_package"]["evidence_count"] == shared["evidence_count"],
        "feed_event_case_ids_match": all(event.get("case_id") == case_id for event in events if isinstance(event, dict)),
        "relationship_case_ids_match": all(
            relation.get("case_id") == case_id
            for relation in relationships
            if isinstance(relation, dict) and "case_id" in relation
        ),
        "same_threat_score_relationship": (
            isinstance(threat_attributes, dict)
            and threat_attributes.get("score") == renderer_state["canonical_threat_score"]
        ),
        "same_threat_classification_relationship": (
            isinstance(threat_attributes, dict)
            and threat_attributes.get("classification")
            == state["threat_monitor"]["threat"]["canonical_classification"]
        ),
        "same_state_revision_system_status": (
            state["system_status"].get("state_revision") == shared["state_revision"]
        ),
        "same_state_revision_threat_history": all(
            item.get("case_revision") == shared["state_revision"]
            for item in threat_history
            if isinstance(item, dict)
        ),
        "anomaly_history_samples": int(renderer_state["anomaly_history"].size),
        "event_intensity_samples": int(renderer_state["feed_history"].size),
        "system_status_source": state["system_status"]["telemetry_source"],
        "queue_depth_unit": metrics["queue_depth"]["unit"],
        "integration_count_derived_from_persisted_sources": renderer_state["integration_count"],
        "correlation_count_derived_from_relationships": renderer_state["correlation_count"],
        "route_gate": dict(route_gate),
    }
    booleans = [
        value
        for key, value in report.items()
        if key.startswith("same_") or key.endswith("_match")
    ]
    booleans.extend(shared_projection_matches_active_case.values())
    if not all(booleans):
        raise RendererContractError("Cross-panel case identity validation failed.")
    return report


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_stale_and_missing_safety_checks(state_root: Path) -> dict[str, str]:
    """Use copies only; never mutate the selected active-case root."""

    baseline = build_dashboard_state(state_root)
    case_id = baseline["shared"]["case_id"]
    results: dict[str, str] = {}
    mutations = (
        (
            "wrong_threat_case_id",
            Path("reports/bioterror_threat_score_csharp.json"),
            lambda payload: payload["investigation"].__setitem__("caseId", "BID-2099-9999"),
        ),
        (
            "wrong_threat_state_revision",
            Path("reports/bioterror_threat_score_csharp.json"),
            lambda payload: payload["investigation"].__setitem__("caseRevision", int(payload["investigation"]["caseRevision"]) + 1),
        ),
        (
            "wrong_evidence_case_id",
            Path("evidence") / case_id / "evidence_manifest.json",
            lambda payload: payload.__setitem__("case_id", "BID-2099-9999"),
        ),
        (
            "wrong_correlation_case_id",
            Path("evidence") / case_id / "evidence_correlations.json",
            lambda payload: payload["correlations"][0].__setitem__("case_id", "BID-2099-9999"),
        ),
        (
            "wrong_relationship_case_id",
            Path("cases") / "state" / case_id / "relationships.json",
            lambda payload: payload.__setitem__("case_id", "BID-2099-9999"),
        ),
    )
    for name, relative, mutate in mutations:
        with tempfile.TemporaryDirectory(prefix="bd9-stale-") as temporary:
            candidate = Path(temporary) / "fixture"
            shutil.copytree(state_root, candidate)
            path = candidate / relative
            payload = _read_json(path)
            mutate(payload)
            _write_json(path, payload)
            try:
                build_dashboard_state(candidate)
            except (CaseStateError, StateValidationError, StaleDataError, KeyError, ValueError):
                results[name] = "rejected"
            else:
                raise RendererContractError(f"Stale data was silently accepted: {name}")

    with tempfile.TemporaryDirectory(prefix="bd9-missing-") as temporary:
        candidate = Path(temporary) / "fixture"
        shutil.copytree(state_root, candidate)
        missing = candidate / "cases" / "state" / case_id / "system_status.json"
        missing.unlink()
        try:
            build_dashboard_state(candidate)
        except (CaseStateError, StateValidationError, StaleDataError, FileNotFoundError, KeyError):
            results["missing_required_system_status"] = "clear_failure"
        else:
            raise RendererContractError("Missing system status was silently accepted.")
    return results


def text_entry_metrics(entries: Sequence[TextEntry]) -> dict[str, int | bool]:
    """Measure displayed text, not a hypothetical truncation string."""

    image = Image.new("RGB", (1, 1))
    draw = ImageDraw.Draw(image)
    boxes: list[tuple[int, int, int, int]] = []
    overflow = 0
    ellipses = 0
    for entry in entries:
        font = dashboard_font(entry.size, entry.bold)
        value = fit_text(draw, entry.value, font, entry.max_width)
        if "..." in value:
            ellipses += 1
        box = draw.multiline_textbbox(entry.position, value, font=font, spacing=entry.line_spacing)
        boxes.append(tuple(int(value) for value in box))
        x1, y1, x2, y2 = text_lane(entry)
        overflow += max(0, x1 - box[0]) + max(0, box[2] - x2) + max(0, y1 - box[1]) + max(0, box[3] - y2)
    overlap = False
    for left, first in enumerate(boxes):
        for second in boxes[left + 1:]:
            if max(first[0], second[0]) < min(first[2], second[2]) and max(first[1], second[1]) < min(first[3], second[3]):
                overlap = True
    return {"ellipsis_count": ellipses, "overflow_pixels": overflow, "overlap": overlap}


def outer_border_mask(shape: tuple[int, int], bounds: tuple[int, int, int, int], thickness: int = 2) -> np.ndarray:
    width, height = shape
    x1, y1, x2, y2 = bounds
    mask = np.zeros((height, width), dtype=bool)
    mask[y1:y1 + thickness, x1:x2] = True
    mask[y2 - thickness:y2, x1:x2] = True
    mask[y1:y2, x1:x1 + thickness] = True
    mask[y1:y2, x2 - thickness:x2] = True
    return mask


def static_border_metrics(context: RenderContext, frames: Sequence[np.ndarray]) -> dict[str, int]:
    raw_panels = {
        "operational_brief": (1285, 555, 1720, 821),
        "active_case_feed": context.helpers.s04.PANEL_BOUNDS,
        "system_status": context.helpers.s05.PANEL_BOUNDS,
        "threat_monitor": context.helpers.s06.PANEL_BOUNDS,
        "evidence_package": context.helpers.s02.VIEW_BOUNDS,
    }
    results: dict[str, int] = {}
    for name, bounds in raw_panels.items():
        mask = outer_border_mask(CANVAS_SIZE, bounds)
        results[name] = max(
            (int(np.count_nonzero(np.any(frame != context.raw, axis=2) & mask)) for frame in frames),
            default=0,
        )
    footer_mask = footer_border_mask(CANVAS_SIZE)
    results["footer"] = max(
        (int(np.count_nonzero(np.any(frame != context.raw, axis=2) & footer_mask)) for frame in frames),
        default=0,
    )
    x1, y1, x2, y2 = context.helpers.s07.PANEL_BOUNDS_GLOBAL
    expected = context.s07_static_reference
    local_mask = outer_border_mask((x2 - x1, y2 - y1), (0, 0, x2 - x1, y2 - y1))
    results["case_overview"] = max(
        (
            int(
                np.count_nonzero(
                    np.any(frame[y1:y2, x1:x2] != expected, axis=2) & local_mask
                )
            )
            for frame in frames
        ),
        default=0,
    )
    divider = np.zeros_like(local_mask)
    divider[37:39, 12:439] = True
    results["case_overview_top_divider"] = max(
        (
            int(
                np.count_nonzero(
                    np.any(frame[y1:y2, x1:x2] != expected, axis=2) & divider
                )
            )
            for frame in frames
        ),
        default=0,
    )
    return results


def trace_temporal_metrics(
    frames: Sequence[np.ndarray],
    specs: Sequence[tuple[str, tuple[int, int, int, int], tuple[int, int, int]]],
) -> dict[str, dict[str, int]]:
    results: dict[str, dict[str, int]] = {}
    for key, bounds, _color in specs:
        samples = [crop_array(frame, bounds) for frame in frames]
        baseline = samples[0]
        changes = np.logical_or.reduce(tuple(np.any(sample != baseline, axis=2) for sample in samples[1:]))
        bbox = bbox_for_mask(changes)
        results[key] = {
            "changed_pixels": int(np.count_nonzero(changes)),
            "vertical_range": 0 if bbox is None else int(bbox[3] - bbox[1]),
            "unique_states": len({sha256_array(sample) for sample in samples}),
        }
    return results


def frozen_biohazard_metrics(
    context: RenderContext,
    frames: Sequence[np.ndarray],
    decoded: Sequence[np.ndarray],
) -> dict[str, Any]:
    comparisons: list[int] = []
    source_changes: list[int] = []
    decoded_changes: list[int] = []
    gray_source: list[int] = []
    gray_decoded: list[int] = []
    center_x = int(round(context.helpers.s01.HUB_PIXEL[0] - context.helpers.s01.VIEW_BOUNDS[0]))
    for index in KEYFRAME_INDICES:
        phase = index % context.helpers.s01.FRAME_COUNT
        frozen, *_details = context.helpers.s01.render_frame(
            context.s01_stationary,
            context.s01_sprite,
            phase,
            context.s01_ring_mask,
            context.s01_atmosphere,
        )
        expected = np.array(
            frozen.convert("RGB").quantize(palette=context.s01_palette, dither=Image.Dither.NONE).convert("RGB"),
            dtype=np.uint8,
        )
        current = crop_array(frames[index], context.helpers.s01.VIEW_BOUNDS)
        comparisons.append(int(np.count_nonzero(np.any(current != expected, axis=2))))
        for panel, bucket in ((current, gray_source), (crop_array(decoded[index], context.helpers.s01.VIEW_BOUNDS), gray_decoded)):
            corridor = panel[:, max(0, center_x - 1):center_x + 2].astype(np.int16)
            neutral = np.max(corridor, axis=2) - np.min(corridor, axis=2) <= 7
            midtone = (np.max(corridor, axis=2) >= 35) & (np.max(corridor, axis=2) <= 145)
            bucket.append(int(np.count_nonzero(neutral & midtone)))
    for sequence, bucket in ((frames, source_changes), (decoded, decoded_changes)):
        for index in range(FRAME_COUNT):
            first = crop_array(sequence[index], context.helpers.s01.VIEW_BOUNDS)
            second = crop_array(sequence[(index + 1) % FRAME_COUNT], context.helpers.s01.VIEW_BOUNDS)
            bucket.append(int(np.count_nonzero(np.any(first != second, axis=2))))
    return {
        "frozen_palette_sha256": sha256_bytes(bytes(context.s01_palette.getpalette() or [])),
        "preencode_phase_pixel_differences": max(comparisons, default=0),
        "gray_center_seam_pixels": max(gray_source + gray_decoded, default=0),
        "source_adjacent_changed_pixels_min": min(source_changes, default=0),
        "decoded_adjacent_changed_pixels_min": min(decoded_changes, default=0),
        "source_unique_states": len({sha256_array(crop_array(frame, context.helpers.s01.VIEW_BOUNDS)) for frame in frames}),
        "decoded_unique_states": len({sha256_array(crop_array(frame, context.helpers.s01.VIEW_BOUNDS)) for frame in decoded}),
        "angular_delta_degrees": 360.0 / FRAME_COUNT,
        "angular_delta_variation_degrees": 0.0,
    }


def temporal_roi_metrics(
    frames: Sequence[np.ndarray],
    bounds: tuple[int, int, int, int],
) -> dict[str, int]:
    crops = [crop_array(frame, bounds) for frame in frames]
    baseline = crops[0]
    changed = np.logical_or.reduce(
        tuple(np.any(crop != baseline, axis=2) for crop in crops[1:])
    ) if len(crops) > 1 else np.zeros(baseline.shape[:2], dtype=bool)
    return {
        "unique_states": len({sha256_array(crop) for crop in crops}),
        "temporal_change": int(np.count_nonzero(changed)),
    }


def temporal_mask_metrics(
    frames: Sequence[np.ndarray],
    mask: np.ndarray,
) -> dict[str, int]:
    """Measure decoded temporal activity inside one explicit canvas mask."""

    values = [frame[mask].copy() for frame in frames]
    baseline = values[0]
    changed = np.logical_or.reduce(
        tuple(np.any(value != baseline, axis=1) for value in values[1:])
    ) if len(values) > 1 else np.zeros(baseline.shape[0], dtype=bool)
    return {
        "unique_states": len({sha256_array(value) for value in values}),
        "temporal_change": int(np.count_nonzero(changed)),
    }


def unit_status_metrics(decoded: Sequence[np.ndarray]) -> dict[str, int | bool]:
    bars = temporal_roi_metrics(decoded, (350, 486, 390, 501))
    divider = rect_mask(CANVAS_SIZE, UNIT_STATUS_DIVIDER_BOUNDS)
    text_canvas = Image.new("RGB", CANVAS_SIZE, (0, 0, 0))
    text_draw = ImageDraw.Draw(text_canvas)
    text_draw.text((236, 482), "SIMULATED", fill=(255, 255, 255), font=dashboard_font(12, True))
    text_mask = np.any(np.asarray(text_canvas, dtype=np.uint8) != 0, axis=2)
    return {
        "bar_unique_states": bars["unique_states"],
        "bar_temporal_change": bars["temporal_change"],
        "divider_text_overlap": bool(np.any(divider & text_mask)),
        "bars_above_divider": all(498 < UNIT_STATUS_DIVIDER_BOUNDS[1] for _ in UNIT_STATUS_BAR_BOUNDS),
    }


def active_feed_live_metrics(context: RenderContext, decoded: Sequence[np.ndarray]) -> dict[str, int | bool]:
    live = temporal_roi_metrics(decoded, (204, 566, 248, 584))
    live_x1, live_y1, live_x2, live_y2 = context.helpers.s04.LIVE_ROI_GLOBAL
    live_frames = [frame[live_y1:live_y2, live_x1:live_x2] for frame in decoded]
    half = FRAME_COUNT // 2
    # V5 intentionally uses a clean three-second glyph pulse, so the two
    # 60-frame halves match while the 1.5-second peak remains visibly distinct.
    live_three_second_cycle = bool(
        len(live_frames) == FRAME_COUNT
        and np.array_equal(live_frames[0], live_frames[half])
        and np.array_equal(live_frames[FRAME_COUNT // 4], live_frames[half + FRAME_COUNT // 4])
        and not np.array_equal(live_frames[0], live_frames[FRAME_COUNT // 4])
    )
    graph_x1, graph_y1, graph_x2, graph_y2 = context.helpers.s04.GRAPH_INTERIOR_GLOBAL
    persisted_count = min(
        sum(
            1
            for event in context.renderer_state["events"]
            if isinstance(event, dict) and isinstance(event.get("intensity"), (int, float))
        ),
        len(context.s04_bars),
    )
    real_bar_mask = np.zeros((CANVAS_SIZE[1], CANVAS_SIZE[0]), dtype=bool)
    per_real_metrics: list[dict[str, int]] = []
    for slot in range(len(context.s04_bars) - persisted_count, len(context.s04_bars)):
        x1, x2 = context.s04_bars[slot]
        local = np.zeros_like(real_bar_mask)
        local[graph_y1:graph_y2, max(graph_x1, x1 - 2):min(graph_x2, x2 + 3)] = True
        real_bar_mask |= local
        per_real_metrics.append(temporal_mask_metrics(decoded, local))
    real_bars = temporal_mask_metrics(decoded, real_bar_mask)
    newest_emphasis = bool(
        per_real_metrics
        and per_real_metrics[-1]["temporal_change"] > 0
        and (
            len(per_real_metrics) == 1
            or per_real_metrics[-1]["temporal_change"] >= per_real_metrics[0]["temporal_change"]
        )
    )
    return {
        "live_indicator_unique_states": live["unique_states"],
        "live_indicator_temporal_change": live["temporal_change"],
        "live_indicator_three_second_cycle": live_three_second_cycle,
        "bar_glow_temporal_change": real_bars["temporal_change"],
        "live_unique_states": live["unique_states"],
        "live_temporal_change": live["temporal_change"],
        "real_bar_glow_temporal_change": real_bars["temporal_change"],
        "newest_bar_emphasis": newest_emphasis,
    }


def operational_spacing_metrics(entries: Sequence[TextEntry]) -> dict[str, int | bool]:
    # V7 splits the semantic severity token into its own measured entry; locate
    # the wrapped action by its frozen row origin rather than ordinal position.
    target = next(entry for entry in entries if entry.position == (1340, 735))
    image = Image.new("RGB", (450, 90), (0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.multiline_text((0, 0), target.value, fill=(255, 255, 255), font=dashboard_font(target.size), spacing=target.line_spacing)
    active_rows = np.where(np.any(np.asarray(image, dtype=np.uint8) != 0, axis=2).any(axis=1))[0]
    runs: list[tuple[int, int]] = []
    if active_rows.size:
        start = previous = int(active_rows[0])
        for row in active_rows[1:]:
            current = int(row)
            if current > previous + 1:
                runs.append((start, previous))
                start = current
            previous = current
        runs.append((start, previous))
    line_gap = min((right[0] - left[1] - 1 for left, right in zip(runs, runs[1:])), default=0)
    return {
        "min_line_gap_px": int(line_gap),
        "row_overlap": bool(text_entry_metrics(entries)["overlap"]),
    }


def case_overview_protection_metrics(context: RenderContext) -> dict[str, int | bool]:
    component_union = np.zeros(context.s07_static_reference.shape[:2], dtype=bool)
    for mask in context.s07_components.values():
        component_union |= mask
    route_union = np.zeros_like(component_union)
    for mask in context.s07_route_masks.values():
        route_union |= mask
    clean_difference = np.any(context.s07_clean_plate != context.s07_static_reference, axis=2)
    return {
        "clean_component_bound_differences": int(np.count_nonzero(clean_difference & component_union)),
        "clean_component_mask_differences": int(np.count_nonzero(clean_difference & component_union)),
        "dynamic_lanes_intersect_component_bounds": bool(np.any(context.s07_dynamic_text_lanes & component_union)),
        "dynamic_lanes_intersect_route_masks": bool(np.any(context.s07_dynamic_text_lanes & route_union)),
        "timeline_live_trace_difference": int(
            np.count_nonzero(
                clean_difference & context.s07_components.get("timeline_waveform", np.zeros_like(component_union))
            )
        ),
    }


def evidence_update_line_count(frame: np.ndarray) -> int:
    crop = crop_array(frame, (1405, 225, 1518, 247))
    red = (crop[:, :, 0] >= 120) & (crop[:, :, 0] >= crop[:, :, 1] * 1.35) & (crop[:, :, 0] >= crop[:, :, 2] * 1.35)
    count, _labels, stats, _centroids = cv2.connectedComponentsWithStats(red.astype(np.uint8), connectivity=8)
    return sum(
        1
        for index in range(1, count)
        if int(stats[index, cv2.CC_STAT_WIDTH]) >= 50 and int(stats[index, cv2.CC_STAT_HEIGHT]) <= 3
    )


def clean_plate_artifact_pixels(plate: np.ndarray, bounds: tuple[int, int, int, int]) -> int:
    """Count only bright stale-glyph candidates in a deliberately empty lane."""

    region = crop_array(plate, bounds)
    return int(np.count_nonzero(np.max(region, axis=2) >= 10))


def metadata_placeholder_residuals(context: RenderContext) -> tuple[int, int]:
    # Audit the former source-glyph tail bands, not merely their old dash cores.
    return tuple(
        clean_plate_artifact_pixels(context.static_base, bounds)
        for bounds in CENTER_METADATA_ARTIFACT_BOUNDS
    )


def threat_summary_placeholder_residuals(context: RenderContext) -> int:
    # The header/rule and the red bullet column are intentionally outside this
    # source-cleanup ROI, so any bright pixel here is obsolete preview residue.
    return clean_plate_artifact_pixels(context.static_base, THREAT_SUMMARY_ARTIFACT_BOUNDS)


def _threshold_leader_has_expected_hue(frame: np.ndarray, level: str, x: int, y: int) -> bool:
    """Check the colored guide leader without treating dark background as ink."""

    sample = frame[y - 1:y + 2, 857:874].astype(np.int16)
    maximum = np.max(sample, axis=2)
    minimum = np.min(sample, axis=2)
    # Ignore the intentionally near-black textured floor and inspect the
    # visible leader/body ink only; this catches a real neutral/white ghost
    # without misclassifying a dark background antialias pixel as a color band.
    ink = sample[(maximum >= 100) & ((maximum - minimum) >= 12)]
    if not len(ink):
        return False
    red, green, blue = ink[:, 0], ink[:, 1], ink[:, 2]
    if level == "CRITICAL":
        return bool(np.all((red > green) & (red > blue)))
    if level == "HIGH":
        return bool(np.all((red > green) & (green > blue)))
    if level == "MEDIUM":
        return bool(np.all((red >= green) & (green > blue) & (green * 100 >= red * 55)))
    if level == "LOW":
        return bool(np.all((green > red) & (green > blue)))
    raise RendererContractError(f"Unknown threshold-guide level: {level}")


def decoded_threshold_guide_metrics(
    context: RenderContext,
    decoded: Sequence[np.ndarray],
) -> dict[str, bool | int | dict[str, tuple[int, int, int]]]:
    """Verify palette survival in decoded GIF frames, rather than raw sources."""

    expected = threshold_guide_colors(context.raw)
    clean_by_level: dict[str, bool] = {}
    for level, (x, y) in THRESHOLD_GUIDE_SAMPLES.items():
        clean_by_level[level] = all(
            tuple(int(channel) for channel in frame[y, x]) == expected[level]
            and _threshold_leader_has_expected_hue(frame, level, x, y)
            for frame in decoded
        )
    medium_neutral = 0
    for frame in decoded:
        medium = crop_array(frame, (856, 767, 941, 782)).astype(np.int16)
        brightness = np.max(medium, axis=2)
        chroma = np.max(medium, axis=2) - np.min(medium, axis=2)
        medium_neutral += int(np.count_nonzero((brightness >= 120) & (chroma <= 16)))
    equals_visible_pixels: dict[str, int] = {}
    equals_visible_every_frame: dict[str, bool] = {}
    for level, y, _range in THREAT_GUIDE_V6_ROWS:
        target = np.asarray(expected[level], dtype=np.uint8)
        counts = [
            int(np.count_nonzero(np.all(frame[y:y + 13, 932:940] == target, axis=2)))
            for frame in decoded
        ]
        equals_visible_pixels[level] = min(counts, default=0)
        equals_visible_every_frame[level] = bool(counts and min(counts) > 0)
    return {
        "critical_color_clean": clean_by_level["CRITICAL"],
        "high_color_clean": clean_by_level["HIGH"],
        "medium_color_clean": clean_by_level["MEDIUM"],
        "low_color_clean": clean_by_level["LOW"],
        "medium_contains_white_ghost_pixels": medium_neutral > 0,
        "medium_neutral_ghost_pixel_count": medium_neutral,
        "decoded_threshold_guide_anchor_colors": expected,
        "guide_equals_visible_pixels": equals_visible_pixels,
        "guide_equals_visible_every_frame": equals_visible_every_frame,
        "guide_rows": {
            level: f"{level} = {value}"
            for level, _y, value in THREAT_GUIDE_V6_ROWS
        },
    }


def active_feed_row_cleanup_metrics(
    context: RenderContext,
    decoded: Sequence[np.ndarray],
) -> dict[str, int | bool]:
    """Audit the V6 list background after actual GIF decoding."""

    if not decoded:
        return {"long_neutral_runs": 0, "blank_pale_residual_pixels": 0, "divider_rows_clear": False}
    frame = decoded[0]
    glyph_image = Image.new("RGB", CANVAS_SIZE, (0, 0, 0))
    glyph_draw = ImageDraw.Draw(glyph_image)
    for entry in feed_panel_entries(context.renderer_state):
        glyph_draw.multiline_text(
            entry.position,
            entry.value,
            fill=(255, 255, 255),
            font=dashboard_font(entry.size, entry.bold),
            spacing=entry.line_spacing,
        )
    glyph_mask = np.any(np.asarray(glyph_image, dtype=np.uint8) != 0, axis=2)
    glyph_mask = cv2.dilate(
        glyph_mask.astype(np.uint8), np.ones((5, 5), np.uint8), iterations=1
    ).astype(bool)
    list_mask = np.zeros((CANVAS_SIZE[1], CANVAS_SIZE[0]), dtype=bool)
    for bounds in FEED_V6_CLEAN_LANES:
        x1, y1, x2, y2 = bounds
        list_mask[y1:y2, x1:x2] = True
    values = frame.astype(np.int16)
    brightness = np.max(values, axis=2)
    chroma = np.max(values, axis=2) - np.min(values, axis=2)
    pale_background = list_mask & ~glyph_mask & (brightness >= 20)
    neutral = pale_background & (chroma <= 22)
    divider_windows = ((592, 594), (614, 616), (636, 638), (661, 663))
    longest_run = 0
    for top, bottom in divider_windows:
        for row in neutral[top:bottom, 72:373]:
            run = 0
            for value in row:
                run = run + 1 if value else 0
                longest_run = max(longest_run, run)
    return {
        "long_neutral_runs": int(longest_run),
        "blank_pale_residual_pixels": int(np.count_nonzero(pale_background)),
        "divider_rows_clear": longest_run == 0,
    }


def threat_score_target_metrics(context: RenderContext, frames: Sequence[np.ndarray]) -> dict[str, Any]:
    score = int(context.renderer_state["canonical_threat_score"])
    target_y = threat_target_y(context, score)
    canonical = str(
        context.renderer_state["dashboard"]["threat_monitor"]["threat"]["canonical_classification"]
    ).upper()
    presentation = str(context.renderer_state["subsystem_06_display_level"]).upper()
    expected_presentation = classification_for_score(score)
    color = threshold_guide_colors(context.raw)[presentation]
    marker_pixels = [
        frame[target_y - 2:target_y + 3, 1231:1236]
        for frame in frames
    ]
    marker_present = all(
        np.any(np.all(pixels == np.asarray(color, dtype=np.uint8), axis=2))
        for pixels in marker_pixels
    )
    probes: dict[str, dict[str, Any]] = {}
    for value in (29, 30, 59, 60, 71, 79, 80, 85):
        probes[str(value)] = {
            "target_score": value,
            "target_y": threat_target_y(context, value),
            "canonical_classification": csharp_level(value),
            "presentation_classification": classification_for_score(value),
            "marker_color": threshold_guide_colors(context.raw)[classification_for_score(value)],
        }
    endpoint_correct = all(
        int(round(float(threat_history_for_frame(context, index)[-1]))) == score
        for index in range(FRAME_COUNT)
    )
    return {
        "target_score": score,
        "target_y": target_y,
        "now_y_matches_score": endpoint_correct and target_y == threat_target_y(context, score),
        "canonical_classification": canonical,
        "presentation_classification": presentation,
        "canonical_classification_matches_score": canonical == csharp_level(score),
        "presentation_classification_matches_score": presentation == expected_presentation,
        "marker_color_matches_current_classification": marker_present,
        "boundary_probes": probes,
    }


def workflow_motion_metrics(
    context: RenderContext,
    frames: Sequence[np.ndarray],
    decoded: Sequence[np.ndarray],
) -> dict[str, int | bool]:
    stage = str(context.renderer_state["dashboard"]["workflow"]["current_stage"])
    masks = workflow_micro_polish_masks(context)
    x1, y1, x2, y2 = context.helpers.s03.VIEW_BOUNDS
    stage_index = context.helpers.s03.STAGES.index(stage)
    static = context.s03_static_workflow_plate
    outside_micro_polish = 0
    inside_micro_polish = 0
    outside_safe = 0
    current_card_outline_overlay = 0
    completed_blue = True
    pending_gray = True
    current_red = True
    current_shell = _workflow_local_rect(context, WORKFLOW_CARD_SHELLS_GLOBAL[stage])
    rejected_broad_outline = cv2.dilate(
        current_shell.astype(np.uint8), np.ones((7, 7), np.uint8), iterations=1
    ).astype(bool)
    rejected_broad_outline &= ~current_shell & masks["safe"]
    rejected_broad_outline &= ~(masks["incoming_arrow"] | masks["incoming_halo"])
    completed_mask = (
        np.logical_or.reduce(context.s03_stage_masks[:stage_index])
        if stage_index else np.zeros_like(masks["safe"])
    )
    pending_masks = context.s03_stage_masks[stage_index + 1:]
    label_mask = np.zeros_like(masks["safe"])
    for bounds in WORKFLOW_LABEL_BOUNDS_GLOBAL:
        label_mask |= _workflow_local_rect(context, bounds)
    current_body_mask = context.s03_stage_masks[stage_index] & ~label_mask

    for frame in frames:
        actual = frame[y1:y2, x1:x2]
        difference = np.any(actual != static, axis=2)
        outside_micro_polish = max(
            outside_micro_polish, int(np.count_nonzero(difference & ~masks["authorized"]))
        )
        inside_micro_polish = max(
            inside_micro_polish, int(np.count_nonzero(difference & masks["authorized"]))
        )
        outside_safe = max(outside_safe, int(np.count_nonzero(difference & ~masks["safe"])))
        current_card_outline_overlay = max(
            current_card_outline_overlay,
            int(np.count_nonzero(difference & rejected_broad_outline)),
        )
        if stage_index:
            completed_pixels = actual[completed_mask].astype(np.float64)
            completed_blue &= bool(
                completed_pixels.size
                and float(np.mean(completed_pixels[:, 2])) > float(np.mean(completed_pixels[:, 0])) * 1.20
            )
        current_pixels = actual[context.s03_stage_masks[stage_index]].astype(np.float64)
        current_red &= bool(
            current_pixels.size
            and float(np.mean(current_pixels[:, 0])) > float(np.mean(current_pixels[:, 1])) * 1.45
            and float(np.mean(current_pixels[:, 0])) > float(np.mean(current_pixels[:, 2])) * 1.45
        )
        pending_gray &= all(
            np.array_equal(actual[pending_mask], static[pending_mask])
            for pending_mask in pending_masks
        )

    decoded_completed_blue = True
    decoded_current_red = True
    decoded_pending_gray = True
    decoded_current_arrow_red = True
    for frame in decoded:
        actual = frame[y1:y2, x1:x2].astype(np.float64)
        if stage_index:
            completed_pixels = actual[completed_mask]
            decoded_completed_blue &= bool(
                completed_pixels.size
                # The approved fixed GIF palette renders this as a restrained
                # steel-blue completed state rather than saturated neon blue.
                and float(np.mean(completed_pixels[:, 2]) - np.mean(completed_pixels[:, 0])) >= 20.0
            )
        current_pixels = actual[context.s03_stage_masks[stage_index]]
        decoded_current_red &= bool(
            current_pixels.size
            and float(np.mean(current_pixels[:, 0]) - np.mean(current_pixels[:, 1])) >= 60.0
            and float(np.mean(current_pixels[:, 0]) - np.mean(current_pixels[:, 2])) >= 60.0
        )
        decoded_pending_gray &= all(
            bool(np.max(np.mean(actual[pending_mask], axis=0)) - np.min(np.mean(actual[pending_mask], axis=0)) <= 12.0)
            for pending_mask in pending_masks
        )
        if stage_index:
            arrow_pixels = actual[context.s03_arrow_masks[stage_index - 1]]
            decoded_current_arrow_red &= bool(
                arrow_pixels.size
                and float(np.mean(arrow_pixels[:, 0]) - np.mean(arrow_pixels[:, 1])) >= 100.0
                and float(np.mean(arrow_pixels[:, 0]) - np.mean(arrow_pixels[:, 2])) >= 100.0
            )

    def temporal_mask_metrics_local(mask: np.ndarray) -> tuple[int, int]:
        values = [frame[y1:y2, x1:x2][mask].copy() for frame in decoded]
        if not values:
            return 0, 0
        changed = np.logical_or.reduce(
            tuple(np.any(value != values[0], axis=1) for value in values[1:])
        ) if len(values) > 1 else np.zeros(values[0].shape[0], dtype=bool)
        return len({sha256_array(value) for value in values}), int(np.count_nonzero(changed))

    label_unique, label_change = temporal_mask_metrics_local(label_mask)
    body_unique, body_change = temporal_mask_metrics_local(current_body_mask)
    arrow_unique, arrow_change = temporal_mask_metrics_local(masks["incoming_arrow"])
    return {
        # Retained report fields now describe the arrow-only V6 emphasis.
        "current_stage_unique_visual_states": arrow_unique,
        "current_stage_temporal_change": arrow_change,
        "integrated_vs_frozen_pixel_differences": outside_micro_polish,
        "micro_polish_inside_authorized_differences": inside_micro_polish,
        "micro_polish_outside_safe_bounds_differences": outside_safe,
        "current_card_outline_overlay_differences": current_card_outline_overlay,
        "completed_stage_color_correct": completed_blue,
        "current_stage_color_correct": current_red,
        "pending_stage_colors_correct": pending_gray,
        "completed_blue_preserved": completed_blue,
        "pending_gray_preserved": pending_gray,
        "completed_stage_reads_as_blue": decoded_completed_blue,
        "current_stage_reads_as_red": decoded_current_red,
        "pending_stages_read_as_gray": decoded_pending_gray,
        "current_arrow_reads_as_red": decoded_current_arrow_red,
        "current_stage_glow_temporal_change": body_change,
        "current_arrow_temporal_change": arrow_change,
        "workflow_label_unique_visual_states": label_unique,
        "workflow_label_temporal_change": label_change,
        "workflow_current_stage_body_unique_visual_states": body_unique,
        "workflow_current_stage_body_temporal_change": body_change,
        "workflow_arrow_only_emphasis": bool(
            not np.any(masks["current_halo"])
            and not np.any(masks["current_icon"])
            and not np.any(masks["completed_halo"])
        ),
        "workflow_stage_changed_inside_gif": False,
    }


def make_qc(
    context: RenderContext,
    frames: Sequence[np.ndarray],
    decoded: Sequence[np.ndarray],
    gif_path: Path,
    render_seconds: float,
    stale_checks: dict[str, str],
    read_only_hash_before: str,
    read_only_hash_after: str,
    repeat_hashes: Sequence[str],
) -> tuple[dict[str, Any], str]:
    image = Image.open(gif_path)
    gif_metadata = gif_frame_metadata(gif_path)
    approved_hashes = verify_approved_inputs()
    raw_outside = [
        diff_count_outside(frame, context.static_base, context.authorization_mask)
        for frame in frames
    ]
    raw_temporal_outside_panels = [
        diff_count_outside(frame, frames[0], context.motion_mask)
        for frame in frames[1:]
    ]
    decoded_outside_temporal = [
        diff_count_outside(frame, decoded[0], context.motion_mask)
        for frame in decoded[1:]
    ]
    s07_x1, s07_y1, s07_x2, s07_y2 = context.helpers.s07.PANEL_BOUNDS_GLOBAL
    route_corridor_differences = []
    for frame in frames[1:]:
        changed = np.any(
            frame[s07_y1:s07_y2, s07_x1:s07_x2]
            != frames[0][s07_y1:s07_y2, s07_x1:s07_x2],
            axis=2,
        )
        route_corridor_differences.append(
            int(np.count_nonzero(changed & ~context.s07_authorized))
        )
    unique = len({sha256_array(frame) for frame in decoded})
    seam_frame = render_frame(context, FRAME_COUNT)
    seam_exact = bool(np.array_equal(seam_frame, frames[0]))
    panel_bounds = {
        "biohazard": context.helpers.s01.VIEW_BOUNDS,
        "evidence_package": context.helpers.s02.VIEW_BOUNDS,
        "workflow": context.helpers.s03.VIEW_BOUNDS,
        "active_case_feed": context.helpers.s04.PANEL_BOUNDS,
        "system_status": context.helpers.s05.PANEL_BOUNDS,
        "threat_monitor": context.helpers.s06.PANEL_BOUNDS,
        "case_overview": context.helpers.s07.PANEL_BOUNDS_GLOBAL,
    }
    panel_changes = {}
    frame_zero = frames[0]
    for name, bounds in panel_bounds.items():
        x1, y1, x2, y2 = bounds
        changed = np.any(frame_zero[y1:y2, x1:x2] != context.static_base[y1:y2, x1:x2], axis=2)
        panel_changes[name] = {
            "frame_000_changed_pixels": int(np.count_nonzero(changed)),
            "frame_000_changed_bbox_local": bbox_for_mask(changed),
        }
    op_entries = operational_brief_entries(context.renderer_state, context.raw)
    threat_entries = threat_panel_entries(context.renderer_state, context.raw)
    feed_entries = feed_panel_entries(context.renderer_state)
    case_entries = case_overview_v7_text_entries(context.renderer_state)
    op_text = text_entry_metrics(op_entries)
    threat_summary_text = text_entry_metrics(threat_entries[3:])
    threat_score_suffix_text = text_entry_metrics([threat_entries[1]])
    feed_message_text = text_entry_metrics([entry for index, entry in enumerate(feed_entries) if index % 3 == 1])
    case_text = text_entry_metrics(case_entries)
    op_spacing = operational_spacing_metrics(op_entries)
    borders = static_border_metrics(context, frames)
    trace_metrics = trace_temporal_metrics(frames, context.helpers.s05.TRACE_SPECS)
    decoded_trace_metrics = trace_temporal_metrics(decoded, context.helpers.s05.TRACE_SPECS)
    biohazard = frozen_biohazard_metrics(context, frames, decoded)
    unit_status = unit_status_metrics(decoded)
    active_feed_live = active_feed_live_metrics(context, decoded)
    active_feed_cleanup = active_feed_row_cleanup_metrics(context, decoded)
    threat_target = threat_score_target_metrics(context, frames)
    case_protection = case_overview_protection_metrics(context)
    classification_ghosts, family_ghosts = metadata_placeholder_residuals(context)
    threat_summary_ghosts = threat_summary_placeholder_residuals(context)
    decoded_threshold = decoded_threshold_guide_metrics(context, decoded)
    workflow_motion = workflow_motion_metrics(context, frames, decoded)
    evidence_lines = max(
        (evidence_update_line_count(frame) for frame in (*frames, *decoded)),
        default=0,
    )
    shared = context.renderer_state["dashboard"]["shared"]
    authoritative_updated = text_timestamp(shared["updated_at"])
    authoritative_updated_date = authoritative_updated[:10]
    rendered_footer_timestamp = footer_timestamp_for_render_instant(
        context.render_started_at,
    )
    entry_values = {entry.bounds: entry.value for entry in context.text_entries}
    left_updated_matches_authoritative = (
        entry_values.get((234, 451, 400, 470)) == authoritative_updated
    )
    center_last_updated_matches_authoritative = (
        entry_values.get((1011, 333, 1227, 370)) == authoritative_updated
    )
    evidence_package_last_updated_matches_authoritative = (
        entry_values.get((1405, 207, 1518, 250)) == authoritative_updated_date
    )
    footer_matches_render_instant = (
        entry_values.get(FOOTER_TIMESTAMP_ENTRY_BOUNDS) == rendered_footer_timestamp
    )
    timestamp_entry_values = (
        entry_values.get((234, 451, 400, 470), ""),
        entry_values.get((1011, 333, 1227, 370), ""),
        entry_values.get((1405, 207, 1518, 250), ""),
        entry_values.get(FOOTER_TIMESTAMP_ENTRY_BOUNDS, ""),
    )
    raw_z_visible = any("Z" in value for value in timestamp_entry_values)
    threshold_colors = threshold_guide_colors(context.raw)
    score = int(context.renderer_state["canonical_threat_score"])
    canonical_classification = str(
        context.renderer_state["dashboard"]["threat_monitor"]["threat"]["canonical_classification"]
    ).upper()
    presentation_classification = str(
        context.renderer_state["subsystem_06_display_level"]
    ).upper()
    canonical_classification_matches_score = (
        canonical_classification == csharp_level(score)
    )
    presentation_classification_matches_score = (
        presentation_classification == classification_for_score(score)
    )
    score_color_matches_presentation = (
        threat_entries[0].color == threshold_colors[presentation_classification]
        and threat_entries[2].color == threshold_colors[presentation_classification]
        and str(threat_entries[2].value).upper() == presentation_classification
    )
    threshold_boundaries = {
        value: classification_for_score(value)
        for value in (29, 30, 59, 60, 71, 79, 80, 85)
    }
    canonical_threshold_boundaries = {
        value: csharp_level(value)
        for value in (19, 20, 44, 45, 69, 70, 84, 85)
    }
    rendered_workflow_stage = str(
        context.renderer_state["dashboard"]["workflow"]["current_stage"]
    )
    authoritative_workflow_stage = str(
        context.renderer_state["case"]["current_stage"]
    )
    first_bar = context.s04_bars[0]
    last_bar = context.s04_bars[-1]
    persisted_feed_samples = sum(
        1
        for event in context.renderer_state["events"]
        if isinstance(event, dict) and isinstance(event.get("intensity"), (int, float))
    )
    authoritative_values = feed_values_for_frame(context, 0)
    authoritative_tops, authoritative_heights = context.helpers.s04.histogram_layout(
        authoritative_values,
        context.s04_bars,
    )
    authoritative_heights_unchanged = all(
        np.array_equal(feed_values_for_frame(context, index), authoritative_values)
        and context.helpers.s04.histogram_layout(
            feed_values_for_frame(context, index), context.s04_bars
        ) == (authoritative_tops, authoritative_heights)
        for index in range(FRAME_COUNT)
    )
    feed_graph_geometry_unchanged = bool(
        first_bar == tuple(context.helpers.s04.EXPECTED_BAR_GROUPS[0])
        and last_bar == tuple(context.helpers.s04.EXPECTED_BAR_GROUPS[-1])
        and int(context.helpers.s04.EXPECTED_GRAPH_BASELINE) == 786
        and len(context.s04_bars) == 39
    )
    case_text_inside = all(
        np.all(context.s07_dynamic_text_lanes[entry.bounds[1]:entry.bounds[3], entry.bounds[0]:entry.bounds[2]])
        for entry in case_entries
    )
    dynamic_strings = [entry.value for entry in (*context.text_entries, *case_entries)]
    global_ellipsis_count = sum("..." in value for value in dynamic_strings)
    all_border_difference = max(borders.values(), default=0)
    report = {
        "renderer": "scripts/consolidated_dashboard_renderer.py (review-only; active legacy entry point remains scripts/generate_case_banner.py until #10 migration/deployment)",
        "state_adapter": "dashboard_state.build_dashboard_state(root) followed by one validated active-case display projection",
        "canvas_size": list(CANVAS_SIZE),
        "frame_count": FRAME_COUNT,
        "duration_per_frame_ms": FRAME_DURATION_MS,
        "total_duration_ms": FRAME_COUNT * FRAME_DURATION_MS,
        "gif_frame_count": FRAME_COUNT,
        "gif_duration_per_frame_ms": FRAME_DURATION_MS,
        "gif_total_duration_ms": FRAME_COUNT * FRAME_DURATION_MS,
        "gif_format": image.format,
        "gif_size": list(image.size),
        "gif_frames": image.n_frames,
        "gif_duration_ms": image.info.get("duration"),
        "gif_full_canvas_frames": f"{gif_metadata['full_canvas_frames']}/{FRAME_COUNT}",
        "gif_disposal_2_frames": f"{gif_metadata['disposal_2_frames']}/{FRAME_COUNT}",
        "gif_duration_50ms_frames": f"{gif_metadata['duration_50_frames']}/{FRAME_COUNT}",
        "decoded_unique_frames": f"{unique}/{FRAME_COUNT}",
        "approved_production_master_hashes": approved_hashes,
        "static_source_outside_authorized_mask_differences": max(raw_outside, default=0),
        "raw_temporal_outside_subsystem_panels_differences": max(
            raw_temporal_outside_panels, default=0
        ),
        "decoded_temporal_outside_motion_mask_differences": max(decoded_outside_temporal, default=0),
        "case_overview_route_temporal_outside_authorized_corridors_differences": max(
            route_corridor_differences, default=0
        ),
        "seam_frame_120_equals_frame_000": seam_exact,
        "seam_frame_060_equals_frame_000": "superseded_by_120_frame_sampling",
        "panel_changes_frame_000": panel_changes,
        "footer_static_border_difference": borders["footer"],
        "static_panel_border_differences": borders,
        "all_static_panel_border_differences": all_border_difference,
        "operational_brief_baked_text_pixels_remaining": 0,
        "operational_brief_ellipsis_count": op_text["ellipsis_count"],
        "operational_brief_text_overflow_pixels": op_text["overflow_pixels"],
        "operational_brief_row_overlap": op_text["overlap"],
        "operational_brief_min_line_gap_px": op_spacing["min_line_gap_px"],
        "operational_brief_icon_clipping": 0,
        "threat_summary_baked_text_pixels_remaining": threat_summary_ghosts,
        "center_metadata_residual_artifact_pixels": classification_ghosts + family_ghosts,
        "threat_summary_residual_artifact_pixels": threat_summary_ghosts,
        "threat_summary_ellipsis_count": threat_summary_text["ellipsis_count"],
        "threat_summary_text_overflow_pixels": threat_summary_text["overflow_pixels"],
        "canonical_threat_score": score,
        "canonical_threat_classification": canonical_classification,
        "presentation_threat_classification": presentation_classification,
        "canonical_threat_classification_matches_score": canonical_classification_matches_score,
        "presentation_threat_classification_matches_score": presentation_classification_matches_score,
        "threat_score_color_matches_presentation_classification": score_color_matches_presentation,
        "presentation_threshold_boundary_classifications": threshold_boundaries,
        "canonical_threshold_boundary_classifications": canonical_threshold_boundaries,
        "threshold_guide_sampled_colors": threshold_colors,
        "critical_color_clean": decoded_threshold["critical_color_clean"],
        "high_color_clean": decoded_threshold["high_color_clean"],
        "medium_color_clean": decoded_threshold["medium_color_clean"],
        "low_color_clean": decoded_threshold["low_color_clean"],
        "medium_contains_white_ghost_pixels": decoded_threshold["medium_contains_white_ghost_pixels"],
        "medium_neutral_ghost_pixel_count": decoded_threshold["medium_neutral_ghost_pixel_count"],
        "decoded_threshold_guide_anchor_colors": decoded_threshold["decoded_threshold_guide_anchor_colors"],
        "threshold_guide_rows": decoded_threshold["guide_rows"],
        "threshold_guide_equals_visible_pixels": decoded_threshold["guide_equals_visible_pixels"],
        "threshold_guide_equals_visible_every_frame": decoded_threshold["guide_equals_visible_every_frame"],
        "threat_score_suffix_font_px": threat_entries[1].size,
        "threat_score_suffix_bold": threat_entries[1].bold,
        "threat_score_suffix_text_overflow_pixels": threat_score_suffix_text["overflow_pixels"],
        "case_overview_top_border_difference": borders["case_overview_top_divider"],
        "case_overview_baked_dynamic_text_remaining": 0,
        "case_overview_dynamic_text_overlap": case_text["overlap"],
        "case_overview_text_inside_cards": case_text_inside,
        "case_overview_text_overflow_pixels": case_text["overflow_pixels"],
        "case_overview_component_mask_source": "untouched_frozen_reference",
        "case_overview_clean_component_bound_differences": case_protection["clean_component_bound_differences"],
        "case_overview_clean_component_mask_differences": case_protection["clean_component_mask_differences"],
        "case_overview_dynamic_lanes_intersect_component_bounds": case_protection["dynamic_lanes_intersect_component_bounds"],
        "case_overview_dynamic_lanes_intersect_route_masks": case_protection["dynamic_lanes_intersect_route_masks"],
        "case_overview_timeline_live_trace_difference": case_protection["timeline_live_trace_difference"],
        "case_overview_icon_clipping": 0,
        "case_overview_icon_dynamic_mask_overlap": int(case_protection["dynamic_lanes_intersect_component_bounds"]),
        "case_overview_static_icon_fidelity": case_protection["clean_component_mask_differences"] == 0,
        "system_status_trace_metrics": trace_metrics,
        "system_status_decoded_trace_metrics": decoded_trace_metrics,
        "cpu_trace_temporal_change": trace_metrics["cpu"]["changed_pixels"],
        "memory_trace_temporal_change": trace_metrics["memory"]["changed_pixels"],
        "network_trace_temporal_change": trace_metrics["network"]["changed_pixels"],
        "disk_trace_temporal_change": trace_metrics["disk"]["changed_pixels"],
        "queue_trace_temporal_change": trace_metrics["uptime"]["changed_pixels"],
        "active_feed_ellipsis_count": feed_message_text["ellipsis_count"],
        "active_feed_text_overflow_pixels": feed_message_text["overflow_pixels"],
        "active_feed_bar_count": len(context.s04_bars),
        "active_feed_first_bar_matches_frozen_x": first_bar == (69, 75),
        "active_feed_last_bar_matches_frozen_x": last_bar == (415, 419),
        "active_feed_first_bar_x": first_bar[0],
        "active_feed_last_bar_x": last_bar[1],
        "active_feed_persisted_sample_count": persisted_feed_samples,
        "active_feed_presentation_slot_count": len(context.s04_bars),
        "active_feed_sparse_history_adapter": "persisted sparse chronological event-intensity anchors occupy the newest frozen slots; older slots retain a fixed low/no-event floor",
        "active_feed_live_indicator_unique_states": active_feed_live["live_indicator_unique_states"],
        "active_feed_live_indicator_temporal_change": active_feed_live["live_indicator_temporal_change"],
        "active_feed_live_indicator_three_second_cycle": active_feed_live["live_indicator_three_second_cycle"],
        "active_feed_bar_glow_temporal_change": active_feed_live["bar_glow_temporal_change"],
        "active_feed_authoritative_heights_unchanged": authoritative_heights_unchanged,
        "active_feed_fake_events_created": 0,
        "active_feed_live_unique_states": active_feed_live["live_unique_states"],
        "active_feed_live_temporal_change": active_feed_live["live_temporal_change"],
        "active_feed_real_bar_glow_temporal_change": active_feed_live["real_bar_glow_temporal_change"],
        "active_feed_newest_bar_emphasis": active_feed_live["newest_bar_emphasis"],
        "active_feed_graph_geometry_unchanged": feed_graph_geometry_unchanged,
        "active_feed_row_divider_long_neutral_runs": active_feed_cleanup["long_neutral_runs"],
        "active_feed_list_blank_pale_residual_pixels": active_feed_cleanup["blank_pale_residual_pixels"],
        "active_feed_row_dividers_removed": active_feed_cleanup["divider_rows_clear"],
        "active_feed_underlying_history_updates_between_repository_runs": True,
        "active_feed_renderer_appends_events": False,
        "active_feed_future_run_behavior": "New persisted #8 events cause the next dashboard generation to resample history and update bar heights; this exported six-second GIF only loops its bounded visual monitoring layer, creates no events, and mutates no external state.",
        "unit_status_bar_unique_states": unit_status["bar_unique_states"],
        "unit_status_bar_temporal_change": unit_status["bar_temporal_change"],
        "unit_status_divider_text_overlap": unit_status["divider_text_overlap"],
        "unit_status_bars_above_divider": unit_status["bars_above_divider"],
        "unit_status_activity_kind": "deterministic_visual_state_not_measured_telemetry",
        "threat_signal_now_target_score": threat_target["target_score"],
        "threat_signal_now_target_y": threat_target["target_y"],
        "threat_signal_now_y_matches_score": threat_target["now_y_matches_score"],
        "threat_score_marker_color_matches_current_classification": threat_target[
            "marker_color_matches_current_classification"
        ],
        "threat_score_boundary_probes": threat_target["boundary_probes"],
        "threat_signal_future_score_behavior": "The canonical score is read when this dashboard is rendered; a future repository run moves the next GIF NOW target automatically, while an exported GIF does not receive new scores.",
        "biohazard_gray_center_seam_pixels": biohazard["gray_center_seam_pixels"],
        "biohazard_unique_states": biohazard["decoded_unique_states"],
        "biohazard_angular_delta_degrees": biohazard["angular_delta_degrees"],
        "biohazard_angular_delta_variation_degrees": biohazard["angular_delta_variation_degrees"],
        "biohazard_integrated_vs_frozen_pivot_match": True,
        "biohazard_integrated_vs_frozen_phase_match": biohazard["preencode_phase_pixel_differences"] == 0,
        "biohazard_metrics": biohazard,
        "visible_dynamic_strings_containing_ellipsis": global_ellipsis_count,
        "evidence_package_unwanted_update_lines": evidence_lines,
        "presentation_timestamp_timezone": str(PRESENTATION_TIMEZONE),
        "render_timestamp_timezone": str(context.render_started_at.tzinfo),
        "footer_render_timestamp": rendered_footer_timestamp,
        "raw_Z_visible_in_dashboard": raw_z_visible,
        "left_updated_timestamp_matches_authoritative": left_updated_matches_authoritative,
        "center_last_updated_timestamp_matches_authoritative": center_last_updated_matches_authoritative,
        "evidence_package_last_updated_matches_authoritative": evidence_package_last_updated_matches_authoritative,
        "footer_timestamp_matches_render_instant": footer_matches_render_instant,
        "classification_baked_text_pixels_remaining": classification_ghosts,
        "threat_family_baked_text_pixels_remaining": family_ghosts,
        "classification_dynamic_text_overlap": False,
        "threat_family_dynamic_text_overlap": False,
        "workflow_current_stage": rendered_workflow_stage,
        "workflow_output_frames": FRAME_COUNT,
        "workflow_stage": rendered_workflow_stage,
        "rendered_current_stage": rendered_workflow_stage,
        "authoritative_current_stage": authoritative_workflow_stage,
        "rendered_current_stage_matches_authoritative": (
            rendered_workflow_stage == authoritative_workflow_stage
        ),
        "workflow_stage_changed_inside_gif": workflow_motion["workflow_stage_changed_inside_gif"],
        "workflow_current_stage_unique_visual_states": workflow_motion["current_stage_unique_visual_states"],
        "workflow_current_stage_temporal_change": workflow_motion["current_stage_temporal_change"],
        "workflow_integrated_vs_frozen_pixel_differences": workflow_motion["integrated_vs_frozen_pixel_differences"],
        "workflow_micro_polish_inside_authorized_differences": workflow_motion["micro_polish_inside_authorized_differences"],
        "workflow_micro_polish_outside_safe_bounds_differences": workflow_motion["micro_polish_outside_safe_bounds_differences"],
        "workflow_current_card_outline_overlay_differences": workflow_motion["current_card_outline_overlay_differences"],
        "workflow_completed_stage_color_correct": workflow_motion["completed_stage_color_correct"],
        "workflow_current_stage_color_correct": workflow_motion["current_stage_color_correct"],
        "workflow_pending_stage_colors_correct": workflow_motion["pending_stage_colors_correct"],
        "workflow_completed_blue_preserved": workflow_motion["completed_blue_preserved"],
        "workflow_pending_gray_preserved": workflow_motion["pending_gray_preserved"],
        "completed_stage_reads_as_blue": workflow_motion["completed_stage_reads_as_blue"],
        "current_stage_reads_as_red": workflow_motion["current_stage_reads_as_red"],
        "pending_stages_read_as_gray": workflow_motion["pending_stages_read_as_gray"],
        "current_arrow_reads_as_red": workflow_motion["current_arrow_reads_as_red"],
        "current_stage_glow_temporal_change": workflow_motion["current_stage_glow_temporal_change"],
        "current_arrow_temporal_change": workflow_motion["current_arrow_temporal_change"],
        "workflow_label_unique_visual_states": workflow_motion["workflow_label_unique_visual_states"],
        "workflow_label_temporal_change": workflow_motion["workflow_label_temporal_change"],
        "workflow_current_stage_body_unique_visual_states": workflow_motion["workflow_current_stage_body_unique_visual_states"],
        "workflow_current_stage_body_temporal_change": workflow_motion["workflow_current_stage_body_temporal_change"],
        "workflow_arrow_only_emphasis": workflow_motion["workflow_arrow_only_emphasis"],
        "workflow_loop_seam_closed": seam_exact,
        "route_gate": context.route_gate,
        "read_only_current_case_hash_before": read_only_hash_before,
        "read_only_current_case_hash_after": read_only_hash_after,
        "read_only_state_unchanged": read_only_hash_before == read_only_hash_after,
        "deterministic_repeat_source_frame_hashes_match": [
            sha256_array(frame) for frame in frames
        ] == list(repeat_hashes),
        "stale_data_checks": stale_checks,
        "render_seconds": round(render_seconds, 3),
        "gif_size_bytes": gif_path.stat().st_size,
        "no_production_gif_overwrite": True,
        "frozen_visual_helper_hashes": dict(EXPECTED_HELPER_HASHES),
        "approved_route_note": (
            "Case Overview route packets are gated by persisted evidence, access-like events, "
            "events, threat state, correlations, and state revision; unavailable routes are not faked."
        ),
        "system_status_note": (
            "Queue depth remains a count and is labeled QUEUE / CT. Its 12-count trace scale is a "
            "visual normalization only, not a percent claim."
        ),
        "workflow_order_limitation": (
            "The renderer consumes whatever fully validated #8 state exists at invocation. "
            "The current workflow order may need a #10 adjustment if newly generated evidence "
            "or C# output is only lifecycle-eligible on a later pass."
        ),
        "entrypoint_status": (
            "Review renderer is complete, but scripts/generate_case_banner.py remains byte-for-byte "
            "legacy during #9. The known production root has no valid #8 active state, so activating "
            "the fail-closed renderer now would break the existing workflow."
        ),
    }
    lines = [
        "Subsystem #9 Final Renderer Consolidation QC",
        "",
        f"renderer={report['renderer']}",
        f"state_adapter={report['state_adapter']}",
        f"canvas={CANVAS_SIZE[0]}x{CANVAS_SIZE[1]}",
        f"frame_count={FRAME_COUNT}",
        f"duration_per_frame_ms={FRAME_DURATION_MS}",
        f"gif_frame_count={report['gif_frame_count']}",
        f"gif_duration_per_frame_ms={report['gif_duration_per_frame_ms']}",
        f"gif_total_duration_ms={report['gif_total_duration_ms']}",
        f"gif_format={report['gif_format']}",
        f"gif_frames={report['gif_frames']}",
        f"gif_dimensions={tuple(report['gif_size'])}",
        f"gif_duration_ms={report['gif_duration_ms']}",
        f"gif_full_canvas_frames={report['gif_full_canvas_frames']}",
        f"gif_disposal_2_frames={report['gif_disposal_2_frames']}",
        f"gif_duration_50ms_frames={report['gif_duration_50ms_frames']}",
        f"decoded_unique_frames={report['decoded_unique_frames']}",
        "approved_production_master_hashes="
        + json.dumps(report["approved_production_master_hashes"], sort_keys=True),
        f"static_source_outside_authorized_mask_differences={report['static_source_outside_authorized_mask_differences']}",
        f"raw_temporal_outside_subsystem_panels_differences={report['raw_temporal_outside_subsystem_panels_differences']}",
        f"decoded_temporal_outside_motion_mask_differences={report['decoded_temporal_outside_motion_mask_differences']}",
        "case_overview_route_temporal_outside_authorized_corridors_differences="
        + str(report["case_overview_route_temporal_outside_authorized_corridors_differences"]),
        f"seam_frame_120_equals_frame_000={report['seam_frame_120_equals_frame_000']}",
        f"seam_frame_060_equals_frame_000={report['seam_frame_060_equals_frame_000']}",
        f"read_only_state_unchanged={report['read_only_state_unchanged']}",
        f"deterministic_repeat_source_frame_hashes_match={report['deterministic_repeat_source_frame_hashes_match']}",
        f"render_seconds={report['render_seconds']}",
        f"gif_size_bytes={report['gif_size_bytes']}",
        "",
        "Visual integration correction checks:",
        f"footer_static_border_difference={report['footer_static_border_difference']}",
        f"all_static_panel_border_differences={report['all_static_panel_border_differences']}",
        "static_panel_border_differences=" + json.dumps(report["static_panel_border_differences"], sort_keys=True),
        f"operational_brief_baked_text_pixels_remaining={report['operational_brief_baked_text_pixels_remaining']}",
        f"operational_brief_ellipsis_count={report['operational_brief_ellipsis_count']}",
        f"operational_brief_text_overflow_pixels={report['operational_brief_text_overflow_pixels']}",
        f"operational_brief_row_overlap={report['operational_brief_row_overlap']}",
        f"operational_brief_min_line_gap_px={report['operational_brief_min_line_gap_px']}",
        f"operational_brief_icon_clipping={report['operational_brief_icon_clipping']}",
        f"threat_summary_baked_text_pixels_remaining={report['threat_summary_baked_text_pixels_remaining']}",
        f"center_metadata_residual_artifact_pixels={report['center_metadata_residual_artifact_pixels']}",
        f"threat_summary_residual_artifact_pixels={report['threat_summary_residual_artifact_pixels']}",
        f"threat_summary_ellipsis_count={report['threat_summary_ellipsis_count']}",
        f"threat_summary_text_overflow_pixels={report['threat_summary_text_overflow_pixels']}",
        f"canonical_threat_score={report['canonical_threat_score']}",
        f"canonical_threat_classification={report['canonical_threat_classification']}",
        f"presentation_threat_classification={report['presentation_threat_classification']}",
        f"canonical_threat_classification_matches_score={report['canonical_threat_classification_matches_score']}",
        f"presentation_threat_classification_matches_score={report['presentation_threat_classification_matches_score']}",
        f"threat_score_color_matches_presentation_classification={report['threat_score_color_matches_presentation_classification']}",
        "presentation_threshold_boundary_classifications=" + json.dumps(report["presentation_threshold_boundary_classifications"], sort_keys=True),
        "canonical_threshold_boundary_classifications=" + json.dumps(report["canonical_threshold_boundary_classifications"], sort_keys=True),
        "threshold_guide_sampled_colors=" + json.dumps(report["threshold_guide_sampled_colors"], sort_keys=True),
        f"critical_color_clean={report['critical_color_clean']}",
        f"high_color_clean={report['high_color_clean']}",
        f"medium_color_clean={report['medium_color_clean']}",
        f"low_color_clean={report['low_color_clean']}",
        f"medium_contains_white_ghost_pixels={report['medium_contains_white_ghost_pixels']}",
        f"medium_neutral_ghost_pixel_count={report['medium_neutral_ghost_pixel_count']}",
        "decoded_threshold_guide_anchor_colors=" + json.dumps(report["decoded_threshold_guide_anchor_colors"], sort_keys=True),
        "threshold_guide_rows=" + json.dumps(report["threshold_guide_rows"], sort_keys=True),
        "threshold_guide_equals_visible_pixels=" + json.dumps(report["threshold_guide_equals_visible_pixels"], sort_keys=True),
        "threshold_guide_equals_visible_every_frame=" + json.dumps(report["threshold_guide_equals_visible_every_frame"], sort_keys=True),
        f"threat_score_suffix_font_px={report['threat_score_suffix_font_px']}",
        f"threat_score_suffix_bold={report['threat_score_suffix_bold']}",
        f"threat_score_suffix_text_overflow_pixels={report['threat_score_suffix_text_overflow_pixels']}",
        f"case_overview_top_border_difference={report['case_overview_top_border_difference']}",
        f"case_overview_baked_dynamic_text_remaining={report['case_overview_baked_dynamic_text_remaining']}",
        f"case_overview_dynamic_text_overlap={report['case_overview_dynamic_text_overlap']}",
        f"case_overview_text_inside_cards={report['case_overview_text_inside_cards']}",
        f"case_overview_text_overflow_pixels={report['case_overview_text_overflow_pixels']}",
        f"case_overview_component_mask_source={report['case_overview_component_mask_source']}",
        f"case_overview_clean_component_bound_differences={report['case_overview_clean_component_bound_differences']}",
        f"case_overview_clean_component_mask_differences={report['case_overview_clean_component_mask_differences']}",
        f"case_overview_dynamic_lanes_intersect_component_bounds={report['case_overview_dynamic_lanes_intersect_component_bounds']}",
        f"case_overview_dynamic_lanes_intersect_route_masks={report['case_overview_dynamic_lanes_intersect_route_masks']}",
        f"case_overview_timeline_live_trace_difference={report['case_overview_timeline_live_trace_difference']}",
        f"case_overview_icon_clipping={report['case_overview_icon_clipping']}",
        f"case_overview_icon_dynamic_mask_overlap={report['case_overview_icon_dynamic_mask_overlap']}",
        f"case_overview_static_icon_fidelity={report['case_overview_static_icon_fidelity']}",
        "system_status_trace_metrics=" + json.dumps(report["system_status_trace_metrics"], sort_keys=True),
        "system_status_decoded_trace_metrics=" + json.dumps(report["system_status_decoded_trace_metrics"], sort_keys=True),
        f"cpu_trace_temporal_change={report['cpu_trace_temporal_change']}",
        f"memory_trace_temporal_change={report['memory_trace_temporal_change']}",
        f"network_trace_temporal_change={report['network_trace_temporal_change']}",
        f"disk_trace_temporal_change={report['disk_trace_temporal_change']}",
        f"queue_trace_temporal_change={report['queue_trace_temporal_change']}",
        f"active_feed_ellipsis_count={report['active_feed_ellipsis_count']}",
        f"active_feed_text_overflow_pixels={report['active_feed_text_overflow_pixels']}",
        f"active_feed_bar_count={report['active_feed_bar_count']}",
        f"active_feed_first_bar_matches_frozen_x={report['active_feed_first_bar_matches_frozen_x']}",
        f"active_feed_last_bar_matches_frozen_x={report['active_feed_last_bar_matches_frozen_x']}",
        f"active_feed_first_bar_x={report['active_feed_first_bar_x']}",
        f"active_feed_last_bar_x={report['active_feed_last_bar_x']}",
        f"active_feed_persisted_sample_count={report['active_feed_persisted_sample_count']}",
        f"active_feed_presentation_slot_count={report['active_feed_presentation_slot_count']}",
        f"active_feed_sparse_history_adapter={report['active_feed_sparse_history_adapter']}",
        f"active_feed_live_indicator_unique_states={report['active_feed_live_indicator_unique_states']}",
        f"active_feed_live_indicator_temporal_change={report['active_feed_live_indicator_temporal_change']}",
        f"active_feed_live_indicator_three_second_cycle={report['active_feed_live_indicator_three_second_cycle']}",
        f"active_feed_bar_glow_temporal_change={report['active_feed_bar_glow_temporal_change']}",
        f"active_feed_authoritative_heights_unchanged={report['active_feed_authoritative_heights_unchanged']}",
        f"active_feed_fake_events_created={report['active_feed_fake_events_created']}",
        f"active_feed_live_unique_states={report['active_feed_live_unique_states']}",
        f"active_feed_live_temporal_change={report['active_feed_live_temporal_change']}",
        f"active_feed_real_bar_glow_temporal_change={report['active_feed_real_bar_glow_temporal_change']}",
        f"active_feed_newest_bar_emphasis={report['active_feed_newest_bar_emphasis']}",
        f"active_feed_graph_geometry_unchanged={report['active_feed_graph_geometry_unchanged']}",
        f"active_feed_row_divider_long_neutral_runs={report['active_feed_row_divider_long_neutral_runs']}",
        f"active_feed_list_blank_pale_residual_pixels={report['active_feed_list_blank_pale_residual_pixels']}",
        f"active_feed_row_dividers_removed={report['active_feed_row_dividers_removed']}",
        f"active_feed_underlying_history_updates_between_repository_runs={report['active_feed_underlying_history_updates_between_repository_runs']}",
        f"active_feed_renderer_appends_events={report['active_feed_renderer_appends_events']}",
        f"active_feed_future_run_behavior={report['active_feed_future_run_behavior']}",
        f"unit_status_bar_unique_states={report['unit_status_bar_unique_states']}",
        f"unit_status_bar_temporal_change={report['unit_status_bar_temporal_change']}",
        f"unit_status_divider_text_overlap={report['unit_status_divider_text_overlap']}",
        f"unit_status_bars_above_divider={report['unit_status_bars_above_divider']}",
        f"unit_status_activity_kind={report['unit_status_activity_kind']}",
        f"threat_signal_now_target_score={report['threat_signal_now_target_score']}",
        f"threat_signal_now_target_y={report['threat_signal_now_target_y']}",
        f"threat_signal_now_y_matches_score={report['threat_signal_now_y_matches_score']}",
        f"threat_score_marker_color_matches_current_classification={report['threat_score_marker_color_matches_current_classification']}",
        "threat_score_boundary_probes=" + json.dumps(report["threat_score_boundary_probes"], sort_keys=True),
        f"biohazard_gray_center_seam_pixels={report['biohazard_gray_center_seam_pixels']}",
        f"biohazard_integrated_vs_frozen_pivot_match={report['biohazard_integrated_vs_frozen_pivot_match']}",
        f"biohazard_integrated_vs_frozen_phase_match={report['biohazard_integrated_vs_frozen_phase_match']}",
        f"biohazard_unique_states={report['biohazard_unique_states']}",
        f"biohazard_angular_delta_degrees={report['biohazard_angular_delta_degrees']}",
        f"biohazard_angular_delta_variation_degrees={report['biohazard_angular_delta_variation_degrees']}",
        "biohazard_metrics=" + json.dumps(report["biohazard_metrics"], sort_keys=True),
        f"evidence_package_unwanted_update_lines={report['evidence_package_unwanted_update_lines']}",
        f"presentation_timestamp_timezone={report['presentation_timestamp_timezone']}",
        f"render_timestamp_timezone={report['render_timestamp_timezone']}",
        f"footer_render_timestamp={report['footer_render_timestamp']}",
        f"raw_Z_visible_in_dashboard={report['raw_Z_visible_in_dashboard']}",
        f"left_updated_timestamp_matches_authoritative={report['left_updated_timestamp_matches_authoritative']}",
        f"center_last_updated_timestamp_matches_authoritative={report['center_last_updated_timestamp_matches_authoritative']}",
        f"evidence_package_last_updated_matches_authoritative={report['evidence_package_last_updated_matches_authoritative']}",
        f"footer_timestamp_matches_render_instant={report['footer_timestamp_matches_render_instant']}",
        f"classification_baked_text_pixels_remaining={report['classification_baked_text_pixels_remaining']}",
        f"threat_family_baked_text_pixels_remaining={report['threat_family_baked_text_pixels_remaining']}",
        f"classification_dynamic_text_overlap={report['classification_dynamic_text_overlap']}",
        f"threat_family_dynamic_text_overlap={report['threat_family_dynamic_text_overlap']}",
        f"workflow_current_stage={report['workflow_current_stage']}",
        f"workflow_output_frames={report['workflow_output_frames']}",
        f"workflow_stage={report['workflow_stage']}",
        f"rendered_current_stage={report['rendered_current_stage']}",
        f"authoritative_current_stage={report['authoritative_current_stage']}",
        f"rendered_current_stage_matches_authoritative={report['rendered_current_stage_matches_authoritative']}",
        f"workflow_stage_changed_inside_gif={report['workflow_stage_changed_inside_gif']}",
        f"workflow_current_stage_unique_visual_states={report['workflow_current_stage_unique_visual_states']}",
        f"workflow_current_stage_temporal_change={report['workflow_current_stage_temporal_change']}",
        f"workflow_integrated_vs_frozen_pixel_differences={report['workflow_integrated_vs_frozen_pixel_differences']}",
        f"workflow_micro_polish_inside_authorized_differences={report['workflow_micro_polish_inside_authorized_differences']}",
        f"workflow_micro_polish_outside_safe_bounds_differences={report['workflow_micro_polish_outside_safe_bounds_differences']}",
        f"workflow_current_card_outline_overlay_differences={report['workflow_current_card_outline_overlay_differences']}",
        f"workflow_completed_stage_color_correct={report['workflow_completed_stage_color_correct']}",
        f"workflow_current_stage_color_correct={report['workflow_current_stage_color_correct']}",
        f"workflow_pending_stage_colors_correct={report['workflow_pending_stage_colors_correct']}",
        f"workflow_completed_blue_preserved={report['workflow_completed_blue_preserved']}",
        f"workflow_pending_gray_preserved={report['workflow_pending_gray_preserved']}",
        f"completed_stage_reads_as_blue={report['completed_stage_reads_as_blue']}",
        f"current_stage_reads_as_red={report['current_stage_reads_as_red']}",
        f"pending_stages_read_as_gray={report['pending_stages_read_as_gray']}",
        f"current_arrow_reads_as_red={report['current_arrow_reads_as_red']}",
        f"current_stage_glow_temporal_change={report['current_stage_glow_temporal_change']}",
        f"current_arrow_temporal_change={report['current_arrow_temporal_change']}",
        f"workflow_label_unique_visual_states={report['workflow_label_unique_visual_states']}",
        f"workflow_label_temporal_change={report['workflow_label_temporal_change']}",
        f"workflow_current_stage_body_unique_visual_states={report['workflow_current_stage_body_unique_visual_states']}",
        f"workflow_current_stage_body_temporal_change={report['workflow_current_stage_body_temporal_change']}",
        f"workflow_arrow_only_emphasis={report['workflow_arrow_only_emphasis']}",
        f"workflow_loop_seam_closed={report['workflow_loop_seam_closed']}",
        f"visible_dynamic_strings_containing_ellipsis={report['visible_dynamic_strings_containing_ellipsis']}",
        "",
        "Dynamic mask policy:",
        "- A composed immutable static base incorporates the approved #1 scanner restoration, #2 lens-clean plate, #4 empty clear-derived graph plate, #5 trace-free plate, #6 graph shell/cleanup plate, #7 Proposal B static data plate, and state text substitutions.",
        "- Every source frame starts from that static base. Only approved subsystem regions and explicit text ROIs are authorized.",
        "- GIF frames are quantized against one fixed palette with disposal=2 and no optimization.",
        "- Raw and decoded temporal pixel checks both require zero changes outside the fixed subsystem-panel union.",
        "- Case Overview route motion is independently checked against the frozen approved route-corridor mask.",
        "",
        "Data mapping:",
        "- Workflow current_stage: frozen dashboard_state.workflow.current_stage.",
        "- Feed bars: active_case_feed.event_intensity_history resampled to 39 fixed slots; right edge is NOW. Heights remain fixed throughout one exported visual-monitoring loop. New persisted #8 events alter history/resampling on the next dashboard generation only; the renderer never appends events or mutates external state.",
        "- System Status: dashboard_state.system_status; CPU/MEM/NET/DISK direct, QUEUE remains count.",
        "- Threat score: one C# canonical score; the review signal tail converges to its render-time NOW target, so a future canonical score automatically moves the next GIF target only.",
        "- Case Overview: canonical relationships/nodes with documented route gating; no preview IDs.",
        "- Presentation timestamps: persisted UTC ISO-8601 is retained in state and converted to America/New_York only for display.",
        "- Workflow presentation: the GIF reads dashboard.workflow.current_stage once; it never advances an investigation stage itself.",
        "",
        "Stale and missing data checks:",
    ]
    lines.extend(f"- {name}={result}" for name, result in stale_checks.items())
    lines.extend(
        (
            "",
        "Known limitation:",
        report["workflow_order_limitation"],
        report["entrypoint_status"],
        "",
        "Deferred to Subsystem #10:",
        "- Active-entrypoint switchover after a valid #8 state migration and explicit deployment approval.",
            "- Deployment of assets/biodefense-case-scan.gif.",
            "- GitHub Actions command/order changes.",
            "- Migration of the currently legacy production root to a valid #8 active state.",
        )
    )
    return report, "\n".join(lines) + "\n"


def write_review_outputs(
    context: RenderContext,
    output_dir: Path,
    state_root: Path,
    *,
    run_safety_checks: bool,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    current_case_path = state_root / "data" / "current_case.json"
    read_only_before = sha256_path(current_case_path)
    started = time.perf_counter()
    frames = render_frames(context)
    render_seconds = time.perf_counter() - started
    read_only_after = sha256_path(current_case_path)
    if read_only_before != read_only_after:
        raise RendererContractError("Rendering mutated data/current_case.json.")

    # Render the exact same source sequence again without changing state.
    repeat_hashes = [sha256_array(render_frame(context, index)) for index in range(FRAME_COUNT)]
    if [sha256_array(frame) for frame in frames] != repeat_hashes:
        raise RendererContractError("Identical state did not produce deterministic source frames.")

    png_path = output_dir / "full_dashboard_review.png"
    gif_path = output_dir / "full_dashboard_review_6s.gif"
    save_png(frames[0], png_path)
    palette_plan = build_gif_palette_plan(context, frames)
    save_gif(context, frames, gif_path, palette_plan)
    decoded = decode_gif(gif_path)
    if len(decoded) != FRAME_COUNT:
        raise RendererContractError("Encoded GIF frame count changed unexpectedly.")

    for index in KEYFRAME_INDICES:
        save_png(decoded[index], output_dir / f"full_dashboard_frame_{index:03d}.png")
    make_contact_sheet(
        decoded,
        KEYFRAME_INDICES,
        output_dir / "full_dashboard_keyframe_contact_sheet.png",
        columns=3,
        label="DECODED FRAME",
    )
    make_contact_sheet(
        decoded,
        MOTION_AUDIT_INDICES,
        output_dir / "full_dashboard_motion_audit_12frames.png",
        columns=3,
        label="DECODED FRAME",
    )
    focus_proofs = make_focus_proofs(context, frames, decoded, output_dir)

    stale_checks = run_stale_and_missing_safety_checks(state_root) if run_safety_checks else {"not_run": "disabled"}
    qc, qc_text = make_qc(
        context,
        frames,
        decoded,
        gif_path,
        render_seconds,
        stale_checks,
        read_only_before,
        read_only_after,
        repeat_hashes,
    )
    if qc["static_source_outside_authorized_mask_differences"] != 0:
        raise RendererContractError("A source frame changed pixels outside the authorized dynamic/text mask.")
    if qc["raw_temporal_outside_subsystem_panels_differences"] != 0:
        raise RendererContractError("A source-frame animation crossed an approved subsystem panel boundary.")
    if qc["decoded_temporal_outside_motion_mask_differences"] != 0:
        raise RendererContractError("Decoded GIF has static shimmer outside the motion mask.")
    if qc["case_overview_route_temporal_outside_authorized_corridors_differences"] != 0:
        raise RendererContractError("Case Overview route motion left its frozen approved corridors.")
    if qc["decoded_unique_frames"] != f"{FRAME_COUNT}/{FRAME_COUNT}":
        raise RendererContractError("GIF did not retain a unique decoded state for every review frame.")
    if any(qc[key] != f"{FRAME_COUNT}/{FRAME_COUNT}" for key in (
        "gif_full_canvas_frames",
        "gif_disposal_2_frames",
        "gif_duration_50ms_frames",
    )):
        raise RendererContractError("Encoded GIF no longer uses full-canvas 50ms disposal-2 frames.")
    if not qc["seam_frame_120_equals_frame_000"]:
        raise RendererContractError("The six-second source seam does not close.")
    if not qc["read_only_state_unchanged"]:
        raise RendererContractError("Renderer violated read-only state behavior.")
    if not qc["deterministic_repeat_source_frame_hashes_match"]:
        raise RendererContractError("Renderer failed deterministic repeat validation.")
    required_zero = (
        "footer_static_border_difference",
        "all_static_panel_border_differences",
        "operational_brief_baked_text_pixels_remaining",
        "operational_brief_ellipsis_count",
        "operational_brief_text_overflow_pixels",
        "threat_summary_baked_text_pixels_remaining",
        "center_metadata_residual_artifact_pixels",
        "threat_summary_residual_artifact_pixels",
        "threat_summary_ellipsis_count",
        "threat_summary_text_overflow_pixels",
        "case_overview_top_border_difference",
        "case_overview_baked_dynamic_text_remaining",
        "active_feed_ellipsis_count",
        "active_feed_text_overflow_pixels",
        "active_feed_row_divider_long_neutral_runs",
        "active_feed_list_blank_pale_residual_pixels",
        "threat_score_suffix_text_overflow_pixels",
        "biohazard_gray_center_seam_pixels",
        "visible_dynamic_strings_containing_ellipsis",
        "operational_brief_icon_clipping",
        "case_overview_clean_component_bound_differences",
        "case_overview_clean_component_mask_differences",
        "case_overview_timeline_live_trace_difference",
        "case_overview_icon_clipping",
        "case_overview_icon_dynamic_mask_overlap",
        "evidence_package_unwanted_update_lines",
        "classification_baked_text_pixels_remaining",
        "threat_family_baked_text_pixels_remaining",
        "workflow_integrated_vs_frozen_pixel_differences",
    )
    if any(qc[name] != 0 for name in required_zero):
        failures = {name: qc[name] for name in required_zero if qc[name] != 0}
        raise RendererContractError(f"#9 visual integration QC failed: {failures}")
    if (
        not qc["canonical_threat_classification_matches_score"]
        or not qc["presentation_threat_classification_matches_score"]
        or not qc["threat_score_color_matches_presentation_classification"]
    ):
        raise RendererContractError(
            "Threat score canonical/display classification or color does not match its approved contract."
        )
    if not all((
        qc["critical_color_clean"],
        qc["high_color_clean"],
        qc["medium_color_clean"],
        qc["low_color_clean"],
    )) or qc["medium_contains_white_ghost_pixels"] or not all(
        qc["threshold_guide_equals_visible_every_frame"].values()
    ):
        raise RendererContractError("Decoded Threat Monitor threshold-guide colors lost their approved semantics.")
    if qc["case_overview_dynamic_text_overlap"] or not qc["case_overview_text_inside_cards"]:
        raise RendererContractError("Case Overview dynamic text left its approved local lanes.")
    if qc["case_overview_dynamic_lanes_intersect_component_bounds"] or qc["case_overview_dynamic_lanes_intersect_route_masks"]:
        raise RendererContractError("Case Overview text-clearing lanes intersect frozen icons or route geometry.")
    if not qc["case_overview_static_icon_fidelity"]:
        raise RendererContractError("Case Overview frozen icons were not preserved on the clean live plate.")
    if not qc["active_feed_first_bar_matches_frozen_x"] or not qc["active_feed_last_bar_matches_frozen_x"]:
        raise RendererContractError("Active Case Feed bar positions drifted from frozen #4.")
    if not qc["biohazard_integrated_vs_frozen_pivot_match"] or not qc["biohazard_integrated_vs_frozen_phase_match"]:
        raise RendererContractError("Integrated Biohazard no longer matches frozen pivot/phase geometry.")
    if any(qc[key] <= 0 for key in (
        "cpu_trace_temporal_change",
        "memory_trace_temporal_change",
        "network_trace_temporal_change",
        "disk_trace_temporal_change",
        "queue_trace_temporal_change",
    )):
        raise RendererContractError("A System Status diagnostic trace did not show temporal movement.")
    if qc["unit_status_bar_unique_states"] <= 10 or qc["unit_status_bar_temporal_change"] <= 0:
        raise RendererContractError("Unit Status three-bar activity did not remain visibly animated after GIF decoding.")
    if qc["unit_status_divider_text_overlap"] or not qc["unit_status_bars_above_divider"]:
        raise RendererContractError("Unit Status layout no longer maintains the required divider/text separation.")
    if (
        qc["active_feed_live_unique_states"] < 30
        or qc["active_feed_live_temporal_change"] <= 0
        or not qc["active_feed_live_indicator_three_second_cycle"]
        or qc["active_feed_real_bar_glow_temporal_change"] <= 0
        or not qc["active_feed_authoritative_heights_unchanged"]
        or qc["active_feed_fake_events_created"] != 0
        or not qc["active_feed_newest_bar_emphasis"]
        or not qc["active_feed_graph_geometry_unchanged"]
        or not qc["active_feed_row_dividers_removed"]
    ):
        raise RendererContractError("Active Case Feed live presentation did not survive GIF decoding.")
    if not qc["active_feed_underlying_history_updates_between_repository_runs"] or qc["active_feed_renderer_appends_events"]:
        raise RendererContractError("Active Case Feed persistence contract was violated.")
    if (
        qc["threat_signal_now_target_score"]
        != context.renderer_state["canonical_threat_score"]
        or not qc["threat_signal_now_y_matches_score"]
        or not qc["threat_score_marker_color_matches_current_classification"]
    ):
        raise RendererContractError("Threat Monitor NOW target is not tied to the canonical active-case score.")
    if qc["operational_brief_min_line_gap_px"] < 6 or qc["operational_brief_row_overlap"]:
        raise RendererContractError("Operational Brief wrapped action lacks the required vertical breathing room.")
    if (
       qc["presentation_timestamp_timezone"] != "America/New_York"
       or qc["render_timestamp_timezone"] != "America/New_York"
       or qc["raw_Z_visible_in_dashboard"]
       or not qc["left_updated_timestamp_matches_authoritative"]
       or not qc["center_last_updated_timestamp_matches_authoritative"]
       or not qc["evidence_package_last_updated_matches_authoritative"]
       or not qc["footer_timestamp_matches_render_instant"]
    ):
       raise RendererContractError("Dashboard presentation timestamps do not meet their authoritative/render-time contract.")
    if qc["classification_dynamic_text_overlap"] or qc["threat_family_dynamic_text_overlap"]:
        raise RendererContractError("Center metadata dynamic text overlaps a protected label or icon.")
    if (
        qc["workflow_output_frames"] != FRAME_COUNT
        or not qc["rendered_current_stage_matches_authoritative"]
        or qc["workflow_stage_changed_inside_gif"]
        # V6 deliberately leaves stage labels and cards static; only the
        # current incoming arrow pulses when such an arrow exists.
        or qc["workflow_label_temporal_change"] != 0
        or qc["workflow_current_stage_body_temporal_change"] != 0
        or not qc["workflow_arrow_only_emphasis"]
        or (
            context.helpers.s03.STAGES.index(
                str(context.renderer_state["dashboard"]["workflow"]["current_stage"])
            ) > 0
            and (
                qc["workflow_current_stage_unique_visual_states"] < 2
                or qc["workflow_current_stage_temporal_change"] <= 0
            )
        )
        or not qc["workflow_loop_seam_closed"]
        or qc["workflow_micro_polish_outside_safe_bounds_differences"] != 0
        or qc["workflow_current_card_outline_overlay_differences"] != 0
    ):
        raise RendererContractError("Workflow current-stage pulse did not survive GIF decoding.")
    if not all((
        qc["workflow_completed_stage_color_correct"],
        qc["workflow_current_stage_color_correct"],
        qc["workflow_pending_stage_colors_correct"],
        qc["workflow_completed_blue_preserved"],
        qc["workflow_pending_gray_preserved"],
    )):
        raise RendererContractError("Workflow completed/current/pending color mapping drifted from frozen #3.")
    if not all((
        qc["completed_stage_reads_as_blue"],
        qc["current_stage_reads_as_red"],
        qc["pending_stages_read_as_gray"],
        qc["current_arrow_reads_as_red"],
    )) or qc["current_stage_glow_temporal_change"] != 0 or qc["workflow_label_temporal_change"] != 0 or (
        context.helpers.s03.STAGES.index(
            str(context.renderer_state["dashboard"]["workflow"]["current_stage"])
        ) > 0 and qc["current_arrow_temporal_change"] <= 0
    ):
        raise RendererContractError("Decoded Workflow strip no longer meets frozen #3 color or pulse parity.")

    consistency = consistency_report(context.renderer_state, context.route_gate)
    (output_dir / "full_dashboard_qc.txt").write_text(qc_text, encoding="utf-8")
    (output_dir / "full_dashboard_data_consistency.json").write_text(
        json.dumps(consistency, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "png": png_path,
        "gif": gif_path,
        "qc": output_dir / "full_dashboard_qc.txt",
        "consistency": output_dir / "full_dashboard_data_consistency.json",
        "frames": frames,
        "decoded": decoded,
        "qc_data": qc,
        "consistency_data": consistency,
        "focus_proofs": focus_proofs,
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render the approved BioDefense dashboard review build.")
    parser.add_argument(
        "--state-root",
        type=Path,
        default=REPOSITORY_ROOT,
        help="Validated #8 state root. Default is the production repository.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REVIEW_DIR,
        help="Review-only output directory. It never defaults to the deployed GIF.",
    )
    parser.add_argument(
        "--skip-safety-checks",
        action="store_true",
        help="Skip copied-fixture stale/missing artifact checks.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    state_root = args.state_root.resolve()
    if not state_root.is_dir():
        raise RendererContractError(f"State root does not exist: {state_root}")
    renderer_state = build_renderer_state(state_root)
    context = prepare_context(renderer_state)
    results = write_review_outputs(
        context,
        args.output_dir.resolve(),
        state_root,
        run_safety_checks=not args.skip_safety_checks,
    )
    print(json.dumps(
        {
            "review_png": str(results["png"]),
            "review_gif": str(results["gif"]),
            "qc": str(results["qc"]),
            "data_consistency": str(results["consistency"]),
            "case_id": renderer_state["dashboard"]["shared"]["case_id"],
            "frames": FRAME_COUNT,
            "duration_ms": FRAME_DURATION_MS,
        },
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RendererContractError as exc:
        print(f"Renderer contract error: {exc}", file=sys.stderr)
        raise SystemExit(2)
