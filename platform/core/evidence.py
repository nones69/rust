"""
IntentOS Control Surface — Evidence pipeline.

Manages evidence upload, integrity tracking, OCR, chronology, and chain-of-custody.
Evidence is never destroyed — only transformed (with logging).
"""

import hashlib
import time
import threading
from . import config as cfg, logger as log
from .safety import enforce_no_evidence_destruction, enforce_logged_transformation

_lock = threading.RLock()
_evidence_store: dict[str, dict] = {}   # evidence_id → evidence_record


def _make_id(filename: str, content_hash: str) -> str:
    raw = f"{filename}:{content_hash}:{time.time()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def ingest(filename: str, content: bytes, source: str = "upload") -> dict:
    """
    Ingest a piece of evidence.  Returns an evidence record.
    Chain-of-custody entry is always written regardless of logging mode.
    """
    ev_cfg = cfg.get_section("evidence")

    content_hash = hashlib.sha256(content).hexdigest()
    ev_id = _make_id(filename, content_hash)

    record = {
        "id":         ev_id,
        "filename":   filename,
        "size_bytes": len(content),
        "hash":       content_hash,
        "ingested_at": time.time(),
        "source":     source,
        "coc":        [],       # chain-of-custody
        "metadata":   {},
        "text":       None,
        "events":     [],
    }

    if ev_cfg.get("chain_of_custody"):
        record["coc"].append({
            "action":    "ingested",
            "timestamp": time.time(),
            "by":        "system",
            "hash":      content_hash,
        })

    if ev_cfg.get("metadata_extraction"):
        record["metadata"] = {
            "filename": filename,
            "size_kb":  round(len(content) / 1024, 2),
            "type":     _guess_type(filename),
        }
        log.info("evidence", f"Metadata extracted for {ev_id}", record["metadata"])

    if ev_cfg.get("ocr_enabled") and _is_document(filename):
        record["text"] = _simulate_ocr(content)
        _coc_append(record, "ocr_extracted")
        log.info("evidence", f"OCR applied to {ev_id}", {"chars": len(record["text"] or "")})

    if ev_cfg.get("chronology_inference") and record["text"]:
        record["events"] = _simulate_chronology(record["text"])
        _coc_append(record, "chronology_built")
        log.info("evidence", f"Chronology built for {ev_id}",
                 {"event_count": len(record["events"])})

    with _lock:
        _evidence_store[ev_id] = record

    log.audit("evidence", f"Evidence ingested: {filename}", {"id": ev_id, "hash": content_hash})
    return _public_record(record)


def get(ev_id: str) -> dict | None:
    with _lock:
        r = _evidence_store.get(ev_id)
    return _public_record(r) if r else None


def list_all() -> list:
    with _lock:
        return [_public_record(r) for r in _evidence_store.values()]


def transform(ev_id: str, transform_name: str, developer_mode: bool = False) -> dict:
    ev_cfg = cfg.get_section("evidence")
    if ev_cfg.get("safe_mode") and not ev_cfg.get("transformation_mode"):
        raise PermissionError("Evidence transformation requires transformation_mode enabled.")
    if not developer_mode:
        raise PermissionError("Evidence transformation requires developer mode.")

    with _lock:
        if ev_id not in _evidence_store:
            raise KeyError(f"Evidence {ev_id!r} not found.")
        record = _evidence_store[ev_id]

    enforce_logged_transformation(transform_name, ev_id)
    _coc_append(record, f"transformed:{transform_name}")
    log.audit("evidence", f"Evidence transformed: {transform_name}", {"id": ev_id})
    return _public_record(record)


def delete(ev_id: str) -> None:
    """Evidence deletion is always blocked by the hard safety rule."""
    enforce_no_evidence_destruction("delete")


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _public_record(r: dict | None) -> dict | None:
    if r is None:
        return None
    return {k: v for k, v in r.items() if k != "_raw_content"}


def _coc_append(record: dict, action: str) -> None:
    if cfg.get_section("evidence").get("chain_of_custody"):
        record["coc"].append({
            "action":    action,
            "timestamp": time.time(),
            "by":        "system",
        })


def _guess_type(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower()
    return {"pdf": "pdf", "png": "image", "jpg": "image",
            "jpeg": "image", "txt": "text", "docx": "word"}.get(ext, "unknown")


def _is_document(filename: str) -> bool:
    return _guess_type(filename) in ("pdf", "word", "text")


def _simulate_ocr(content: bytes) -> str:
    return (
        "EXTRACTED TEXT [SIMULATED]\n"
        "This document contains evidence relating to the matter.\n"
        "On 2024-01-15 the party signed the agreement.\n"
        "On 2024-06-20 the dispute was formally raised.\n"
        "Amounts referenced: $42,000 and $17,500.\n"
    )


def _simulate_chronology(text: str) -> list:
    import re
    dates = re.findall(r'\d{4}-\d{2}-\d{2}', text)
    return [{"date": d, "summary": f"Event on {d}"} for d in sorted(set(dates))]
