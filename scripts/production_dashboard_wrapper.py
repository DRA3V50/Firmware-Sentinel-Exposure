#!/usr/bin/env python3
"""Compact production wrapper around the frozen Subsystem #9 V2 renderer.

It resolves the repository locally, validates one immutable #8 dashboard
state, renders an external candidate, verifies it, and atomically installs the
candidate assets.  It performs no lifecycle work and never writes active-case
state.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from PIL import Image

from consolidated_dashboard_renderer import (
    CANVAS_SIZE,
    FRAME_COUNT,
    FRAME_DURATION_MS,
    RendererContractError,
    build_renderer_state,
    prepare_context,
    write_review_outputs,
)


FROZEN_V2_SHA256 = "2f55fea6eb570293b51b4d52b76daa8e0fb5a47e56e4e9331c8c09b737f89240"
# Explicit semantic summaries for the approved 205px center-metadata lanes.
# They are display-only aliases: the complete persisted values remain
# authoritative and are never rewritten by this wrapper.
CLASSIFICATION_DISPLAY_ALIASES = {
    "Biomedical Infrastructure Investigation": "BIOMEDICAL INFRASTRUCTURE",
    "Biological Research Intelligence Collection": "BIOLOGICAL RESEARCH INTEL",
    "Biocontainment Network Investigation": "BIOCONTAINMENT NETWORK",
    "Cyber-Biothreat Intelligence Review": "CYBER-BIOTHREAT REVIEW",
    "Digital Evidence Reconstruction Investigation": "DIGITAL EVIDENCE REVIEW",
    "Laboratory Access Control Investigation": "LAB ACCESS CONTROL",
    "Laboratory Security Breach Investigation": "LAB SECURITY BREACH",
    "Medical Device Security Assessment": "MEDICAL DEVICE SECURITY",
    "Protected Research Systems Investigation": "PROTECTED RESEARCH",
    "Research Data Integrity Investigation": "RESEARCH DATA INTEGRITY",
    "Research Facility Intrusion Investigation": "RESEARCH FACILITY INTRUSION",
    "Specimen Management Security Review": "SPECIMEN SECURITY REVIEW",
    "Supply Chain Security Investigation": "SUPPLY CHAIN INVESTIGATION",
    "Unauthorized Research System Access": "UNAUTHORIZED ACCESS",
}

THREAT_FAMILY_DISPLAY_ALIASES = {
    "Access Control Record Manipulation": "ACCESS CONTROL TAMPERING",
    "Biomedical Supply Chain Compromise": "SUPPLY CHAIN COMPROMISE",
    "Biocontainment System Tampering": "BIOCONTAINMENT TAMPERING",
    "Clinical Research Data Manipulation": "CLINICAL DATA MANIPULATION",
    "Credential Misuse": "CREDENTIAL MISUSE",
    "Evidence Repository Manipulation": "EVIDENCE REPO MANIPULATION",
    "Laboratory Information System Compromise": "LAB INFORMATION COMPROMISE",
    "Medical Device Communications Interference": "MEDICAL DEVICE INTERFERENCE",
    "Protected Research Data Exfiltration": "RESEARCH DATA EXFILTRATION",
    "Research Data Integrity Manipulation": "DATA INTEGRITY MANIPULATION",
    "Research Workstation Compromise": "RESEARCH WORKSTATION",
    "Specimen Tracking Manipulation": "SPECIMEN TRACKING",
    "Unauthorized Laboratory Network Access": "UNAUTHORIZED LAB ACCESS",
}


def repository_root(value: Path | None = None) -> Path:
    return (value or Path(__file__).resolve().parents[1]).resolve()


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_frozen_renderer(root: Path) -> str:
    renderer = root / "scripts" / "consolidated_dashboard_renderer.py"
    actual = sha256_path(renderer)
    if actual != FROZEN_V2_SHA256:
        raise RendererContractError(
            "Frozen Subsystem #9 V2 renderer hash mismatch; refusing production render."
        )
    return actual


def atomic_copy(source: Path, destination: Path) -> None:
    """Copy a complete verified file, then atomically replace its destination."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    try:
        with source.open("rb") as input_handle, os.fdopen(descriptor, "wb") as output_handle:
            while chunk := input_handle.read(1024 * 1024):
                output_handle.write(chunk)
            output_handle.flush()
            os.fsync(output_handle.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def atomic_write_text(destination: Path, value: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent, text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def authoritative_state_paths(root: Path, case_id: str) -> list[Path]:
    support_root = root / "cases" / "state" / case_id
    return [
        root / "data" / "current_case.json",
        root / "operations" / "active_operation.json",
        root / "reports" / "bioterror_threat_score_csharp.json",
        root / "evidence" / case_id / "evidence_manifest.json",
        root / "evidence" / case_id / "evidence_correlations.json",
        support_root / "events.json",
        support_root / "anomaly_history.json",
        support_root / "threat_history.json",
        support_root / "system_status.json",
        support_root / "relationships.json",
    ]


def hash_authoritative_state(root: Path, case_id: str) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in authoritative_state_paths(root, case_id):
        if not path.is_file():
            raise RendererContractError(f"Required dashboard state input is missing: {path}")
        hashes[str(path.relative_to(root)).replace("\\", "/")] = sha256_path(path)
    return hashes


def current_revision_threat_projection(
    renderer_state: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, int | str]]:
    """Adapt persisted threat history for frozen-V2's current-snapshot lane.

    The #8 sidecar correctly retains a time series across case revisions.  The
    byte-frozen V2 consistency gate, however, represents the on-screen threat
    report as a current-revision snapshot.  Build that display-only projection
    in memory so no authoritative file, event, telemetry sample, or history
    record is mutated or discarded.
    """

    case = renderer_state.get("case", {})
    revision = case.get("state_revision")
    history = renderer_state.get("dashboard", {}).get("threat_monitor", {}).get(
        "threat_history", []
    )
    if not isinstance(revision, int) or not isinstance(history, list):
        raise RendererContractError("Persistent threat history is not renderable.")
    current = [
        sample
        for sample in history
        if isinstance(sample, dict) and sample.get("case_revision") == revision
    ]
    if not current:
        raise RendererContractError(
            "The persistent threat history has no sample for the active case revision."
        )
    projected = copy.deepcopy(renderer_state)
    projected["dashboard"]["threat_monitor"]["threat_history"] = current
    projected["threat_history_count"] = len(current)
    return projected, {
        "mode": "current_revision_display_projection",
        "authoritative_sample_count": len(history),
        "projected_current_revision_sample_count": len(current),
        "current_state_revision": revision,
    }


def apply_display_text_projection(renderer_state: dict[str, Any]) -> dict[str, Any]:
    """Apply exact-match display aliases without mutating authoritative state.

    Unknown or non-string values deliberately pass through unchanged. The
    frozen renderer remains the fail-closed authority for any value that does
    not fit its approved lane.
    """

    case = renderer_state.get("case")
    display = renderer_state.get("display")
    if not isinstance(case, dict) or not isinstance(display, dict):
        raise RendererContractError("Renderer state is missing the display-only case projection.")

    authoritative_classification = case.get("classification")
    authoritative_threat_family = case.get("threat_family")
    display_classification = (
        CLASSIFICATION_DISPLAY_ALIASES.get(
            authoritative_classification, authoritative_classification
        )
        if isinstance(authoritative_classification, str)
        else authoritative_classification
    )
    display_threat_family = (
        THREAT_FAMILY_DISPLAY_ALIASES.get(
            authoritative_threat_family, authoritative_threat_family
        )
        if isinstance(authoritative_threat_family, str)
        else authoritative_threat_family
    )

    # Replace only the wrapper-local display dictionary. `case` retains the
    # complete persistent values used by the rest of the #8 state contract.
    projected_display = copy.deepcopy(display)
    projected_display["classification"] = display_classification
    projected_display["threat_family"] = display_threat_family
    renderer_state["display"] = projected_display

    return {
        "authoritative_classification": authoritative_classification,
        "display_classification": display_classification,
        "classification_projection_applied": (
            display_classification != authoritative_classification
        ),
        "authoritative_threat_family": authoritative_threat_family,
        "display_threat_family": display_threat_family,
        "threat_family_projection_applied": (
            display_threat_family != authoritative_threat_family
        ),
    }


def inspect_gif(path: Path) -> dict[str, Any]:
    with Image.open(path) as image:
        decoded_hashes: list[str] = []
        full_canvas = 0
        disposal_2 = 0
        duration_50 = 0
        for index in range(image.n_frames):
            image.seek(index)
            tile = image.tile[0][1] if image.tile else None
            if tuple(tile or ()) == (0, 0, *CANVAS_SIZE):
                full_canvas += 1
            if int(getattr(image, "disposal_method", 0)) == 2:
                disposal_2 += 1
            if int(image.info.get("duration", 0)) == FRAME_DURATION_MS:
                duration_50 += 1
            decoded_hashes.append(
                hashlib.sha256(image.convert("RGB").tobytes()).hexdigest()
            )
        return {
            "format": image.format,
            "size": list(image.size),
            "frame_count": image.n_frames,
            "duration_ms": int(image.info.get("duration", 0)),
            "loop": int(image.info.get("loop", -1)),
            "full_canvas_frames": full_canvas,
            "disposal_2_frames": disposal_2,
            "duration_50ms_frames": duration_50,
            "unique_decoded_frames": len(set(decoded_hashes)),
        }


def verify_candidate(gif_path: Path, png_path: Path, qc: dict[str, Any]) -> dict[str, Any]:
    if not png_path.is_file() or not gif_path.is_file():
        raise RendererContractError("The frozen renderer did not create both candidate assets.")
    gif = inspect_gif(gif_path)
    expected = {
        "format": "GIF",
        "size": list(CANVAS_SIZE),
        "frame_count": FRAME_COUNT,
        "duration_ms": FRAME_DURATION_MS,
        "loop": 0,
        "full_canvas_frames": FRAME_COUNT,
        "disposal_2_frames": FRAME_COUNT,
        "duration_50ms_frames": FRAME_COUNT,
        "unique_decoded_frames": FRAME_COUNT,
    }
    for key, value in expected.items():
        if gif[key] != value:
            raise RendererContractError(
                f"Deployment candidate GIF contract failed for {key}: {gif[key]!r} != {value!r}"
            )
    required_zero_metrics = (
        "static_source_outside_authorized_mask_differences",
        "raw_temporal_outside_subsystem_panels_differences",
        "decoded_temporal_outside_motion_mask_differences",
        "case_overview_route_temporal_outside_authorized_corridors_differences",
        "all_static_panel_border_differences",
        "visible_dynamic_strings_containing_ellipsis",
        "biohazard_gray_center_seam_pixels",
        "active_feed_fake_events_created",
    )
    for key in required_zero_metrics:
        if qc.get(key) != 0:
            raise RendererContractError(f"Frozen V2 candidate metric regressed: {key}={qc.get(key)!r}")
    if qc.get("workflow_stage_changed_inside_gif") is not False:
        raise RendererContractError("Workflow stage changed inside the candidate GIF.")
    if qc.get("read_only_state_unchanged") is not True:
        raise RendererContractError("Frozen renderer did not prove read-only state behavior.")
    return {
        "gif": gif,
        "png_sha256": sha256_path(png_path),
        "gif_sha256": sha256_path(gif_path),
        "qc_zero_metrics": {key: qc[key] for key in required_zero_metrics},
        "workflow_stage_changed_inside_gif": qc["workflow_stage_changed_inside_gif"],
        "renderer_mutates_case_state": not qc["read_only_state_unchanged"],
    }


def render_and_deploy(
    root: Path | None = None,
    *,
    candidate_dir: Path | None = None,
    deploy: bool = True,
) -> dict[str, Any]:
    """Render into external staging, verify, then atomically deploy the pair."""

    root = repository_root(root)
    renderer_sha256 = verify_frozen_renderer(root)
    authoritative_renderer_state = build_renderer_state(root)
    renderer_state, threat_projection = current_revision_threat_projection(
        authoritative_renderer_state
    )
    display_projection = apply_display_text_projection(renderer_state)
    case_id = renderer_state["dashboard"]["shared"]["case_id"]
    state_before = hash_authoritative_state(root, case_id)
    context = prepare_context(renderer_state)

    with tempfile.TemporaryDirectory(prefix="biodefense-dashboard-candidate-") as temp:
        staging_dir = Path(temp)
        results = write_review_outputs(
            context,
            staging_dir,
            root,
            run_safety_checks=True,
        )
        state_after = hash_authoritative_state(root, case_id)
        if state_after != state_before:
            changed = sorted(
                key
                for key in set(state_before) | set(state_after)
                if state_before.get(key) != state_after.get(key)
            )
            raise RendererContractError(
                "Rendering modified authoritative state: " + ", ".join(changed)
            )

        verification = verify_candidate(results["gif"], results["png"], results["qc_data"])
        target_candidate = (candidate_dir or root / "assets" / "deployment_candidate").resolve()
        candidate_gif = target_candidate / "biodefense-case-scan.gif"
        candidate_png = target_candidate / "biodefense-dashboard-current.png"
        candidate_qc = target_candidate / "subsystem_10_candidate_qc.json"
        atomic_copy(results["gif"], candidate_gif)
        atomic_copy(results["png"], candidate_png)
        atomic_copy(results["qc"], target_candidate / "full_dashboard_qc.txt")
        atomic_copy(results["consistency"], target_candidate / "full_dashboard_data_consistency.json")
        candidate_record = {
            "wrapper": "scripts/production_dashboard_wrapper.py",
            "case_id": case_id,
            "candidate_gif": str(candidate_gif.relative_to(root)).replace("\\", "/"),
            "candidate_png": str(candidate_png.relative_to(root)).replace("\\", "/"),
            "state_hashes_before": state_before,
            "state_hashes_after": state_after,
            "state_read_only": True,
            "frozen_v2_renderer_sha256": renderer_sha256,
            "threat_history_projection": threat_projection,
            **display_projection,
            "verification": verification,
        }
        atomic_write_text(candidate_qc, json.dumps(candidate_record, indent=2, sort_keys=True) + "\n")

        deployed: dict[str, str] = {}
        if deploy:
            deployed_gif = root / "assets" / "biodefense-case-scan.gif"
            deployed_png = root / "assets" / "biodefense-dashboard-current.png"
            atomic_copy(candidate_gif, deployed_gif)
            atomic_copy(candidate_png, deployed_png)
            deployed = {
                "gif": str(deployed_gif.relative_to(root)).replace("\\", "/"),
                "png": str(deployed_png.relative_to(root)).replace("\\", "/"),
                "gif_sha256": sha256_path(deployed_gif),
                "png_sha256": sha256_path(deployed_png),
            }
            if deployed["gif_sha256"] != verification["gif_sha256"] or deployed[
                "png_sha256"
            ] != verification["png_sha256"]:
                raise RendererContractError("Atomic deployment hashes do not match the verified candidate.")

    return {"case_id": case_id, "candidate": candidate_record, "deployed": deployed}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render, verify, and atomically deploy the approved production dashboard."
    )
    parser.add_argument("--root", type=Path, default=None, help="Repository root.")
    parser.add_argument("--candidate-dir", type=Path, default=None, help="Candidate directory.")
    parser.add_argument("--no-deploy", action="store_true", help="Verify only; do not deploy.")
    args = parser.parse_args()
    try:
        result = render_and_deploy(
            args.root, candidate_dir=args.candidate_dir, deploy=not args.no_deploy
        )
    except RendererContractError as error:
        print(f"Renderer contract error: {error}")
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
