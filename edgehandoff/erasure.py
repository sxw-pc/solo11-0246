"""Real erasure, legal preservation and segmented proof for access logs.

This module is the completion layer behind :mod:`edgehandoff.access_archive`.
The archive only records a local adjudication (an ``erasure_tickets`` row) and
simulated object observations.  It cannot answer the customer's real question:
which exact bytes were destroyed, which bytes remain under a *currently valid*
preservation duty, and who is accountable for every remaining copy.

The model is event sourced through :func:`edgehandoff.store.execute`.  Every
operation is deterministic given its step and the replayed database state:
callers supply ``at`` timestamps and ids, so :func:`edgehandoff.store.replay`
reproduces every row and result.  No wall clock, randomness or network access
is used.

Four responsibilities are implemented here:

* :func:`resolve_scope` -- deletion scope is the conjunction of customer
  identity, domain ownership generation (``claim_epoch``), log generation time
  and the original byte digest.  A later domain holder's epoch is never
  touched, and every old-epoch copy is accounted for.
* :func:`reconcile` / :func:`recover_copy` -- external copies (object versions,
  gateway cache segments, backups) are observed before anything is resent.  A
  destroy that already committed but lost its acknowledgement is *recognised*,
  not re-issued; a notice that arrived in the meantime redirects the copy into
  preservation instead of a blind destroy.
* preservation minimisation -- only records matched by a verified notice
  (issuer, arrival, case scope, release document) are sealed.  Notices are
  effective from actual arrival and are never back-dated.  When safe splitting
  is impossible the whole shared block is quarantined and the over-retention is
  disclosed.
* segmented, append-only proof -- :class:`ComplianceBook` keeps every issued
  deletion proof and preservation schedule.  A false report is never updated in
  place: the original bytes stay and a new correction/amendment is appended.

Two lawful dispositions of the *same* shared compressed block are supported:

* ``split`` -- recompose the unprotected customer records and the other
  tenant's records into independent objects, verify the new digests, seal only
  the minimal preserved fragment, then destroy the original block and every old
  version / replica / cache / backup copy.
* ``quarantine`` -- when the device cannot safely split the block, isolate one
  whole matching copy in a restricted preservation vault, revoke ordinary
  access, destroy the redundant copies and explicitly report that physical
  erasure is incomplete until a verified release and a device-level destruction
  certificate arrive.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from .store import one, rows

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

ERASURE_SCHEMA = """
CREATE TABLE IF NOT EXISTS access_records(
  id TEXT PRIMARY KEY,
  block_id TEXT NOT NULL,
  seq INTEGER,
  customer TEXT NOT NULL,
  host TEXT,
  claim_epoch INTEGER,
  at INTEGER NOT NULL,
  request_ref TEXT,
  scope_tag TEXT,
  digest TEXT,
  byte_count INTEGER DEFAULT 0,
  payload TEXT
);
CREATE TABLE IF NOT EXISTS hold_issuers(
  id TEXT PRIMARY KEY,
  name TEXT,
  kind TEXT,
  trusted INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS hold_notices_rich(
  id TEXT PRIMARY KEY,
  customer TEXT,
  host TEXT,
  claim_epoch INTEGER,
  start_at INTEGER,
  end_at INTEGER,
  request_refs TEXT,
  scope_tag TEXT,
  case_ref TEXT,
  cause TEXT,
  issuer TEXT,
  issued_at INTEGER,
  arrived_at INTEGER,
  valid_until INTEGER,
  claimed_early INTEGER DEFAULT 0,
  status TEXT,
  validation TEXT
);
CREATE TABLE IF NOT EXISTS hold_releases(
  id TEXT PRIMARY KEY,
  notice_id TEXT,
  issuer TEXT,
  case_ref TEXT,
  released_at INTEGER,
  document_ref TEXT,
  verified INTEGER,
  validation TEXT
);
CREATE TABLE IF NOT EXISTS byte_copies(
  id TEXT PRIMARY KEY,
  block_id TEXT,
  replica_id TEXT,
  kind TEXT,
  location TEXT,
  object_key TEXT,
  version TEXT,
  digest TEXT,
  byte_count INTEGER,
  covers TEXT,
  record_ids TEXT,
  state TEXT,
  reachable INTEGER DEFAULT 1,
  responsible TEXT,
  command_id TEXT,
  evidence TEXT
);
CREATE TABLE IF NOT EXISTS external_assets(
  kind TEXT,
  location TEXT,
  object_key TEXT,
  version TEXT,
  digest TEXT,
  byte_count INTEGER,
  state TEXT,
  reachable INTEGER DEFAULT 1,
  attestation TEXT,
  reported_at INTEGER,
  PRIMARY KEY(kind,location,object_key,version)
);
CREATE TABLE IF NOT EXISTS external_commands(
  id TEXT PRIMARY KEY,
  idem_key TEXT UNIQUE,
  copy_id TEXT,
  action TEXT,
  target TEXT,
  state TEXT,
  issued_at INTEGER,
  decided_at INTEGER,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS hold_fragments(
  id TEXT PRIMARY KEY,
  notice_id TEXT,
  block_id TEXT,
  copy_id TEXT,
  minimized INTEGER,
  record_ids TEXT,
  digest TEXT,
  byte_count INTEGER,
  vault TEXT,
  state TEXT,
  sealed_at INTEGER,
  released_at INTEGER,
  destroyed_at INTEGER,
  release_id TEXT,
  device_cert_id TEXT,
  evidence TEXT
);
CREATE TABLE IF NOT EXISTS device_destruction_certs(
  id TEXT PRIMARY KEY,
  copy_id TEXT,
  fragment_id TEXT,
  media_ref TEXT,
  method TEXT,
  issued_by TEXT,
  at INTEGER,
  digest TEXT,
  verification TEXT
);
CREATE TABLE IF NOT EXISTS compliance_docs(
  id TEXT PRIMARY KEY,
  root_id TEXT,
  kind TEXT,
  customer TEXT,
  ticket_id TEXT,
  amends_id TEXT,
  revision INTEGER,
  issued_at INTEGER,
  conclusion TEXT,
  body TEXT,
  body_digest TEXT,
  delivery TEXT
);
CREATE TABLE IF NOT EXISTS scope_resolutions(
  ticket_id TEXT PRIMARY KEY,
  at INTEGER,
  scope TEXT
);
"""


def ensure_schema(db) -> None:
    # Fast no-op on an already-provisioned connection.  This matters because
    # store.execute() opens an explicit BEGIN IMMEDIATE and sqlite3's
    # executescript() commits any open transaction first; we must not trigger
    # that mid-request.  store.connect() provisions the schema up front.
    row = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='access_records'").fetchone()
    if row:
        return
    db.executescript(ERASURE_SCHEMA)


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------

def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_records(record_rows: List[Dict[str, Any]]) -> str:
    material = [[r["id"], r["customer"], r["at"], r.get("request_ref"), r.get("digest")]
                for r in sorted(record_rows, key=lambda r: (r["at"], r["seq"] if r.get("seq") is not None else 0, r["id"]))]
    return digest_bytes(canonical(material))


def _loads(value, default):
    if value is None:
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _j(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _record_ids(copy: Dict[str, Any]) -> List[str]:
    return _loads(copy.get("record_ids"), []) or []


def _evidence(copy: Dict[str, Any]) -> List[Dict[str, Any]]:
    return _loads(copy.get("evidence"), []) or []


def _add_evidence(db, copy_id: str, entry: Dict[str, Any]) -> None:
    copy = one(db, "SELECT evidence FROM byte_copies WHERE id=?", (copy_id,))
    ev = _loads(copy["evidence"] if copy else None, [])
    ev.append(entry)
    db.execute("UPDATE byte_copies SET evidence=? WHERE id=?", (_j(ev), copy_id))


def _set_copy_state(db, copy_id: str, state: str, at: int,
                    evidence_entry: Optional[Dict[str, Any]] = None,
                    responsible: Optional[str] = None) -> None:
    db.execute("UPDATE byte_copies SET state=?" + (", responsible=?" if responsible else "") + " WHERE id=?",
               (state, *((responsible,) if responsible else ()), copy_id))
    if evidence_entry is not None:
        entry = dict(evidence_entry)
        entry.setdefault("at", at)
        _add_evidence(db, copy_id, entry)
    # Keep the legacy archive replica ledger coherent where a row exists.
    copy = one(db, "SELECT * FROM byte_copies WHERE id=?", (copy_id,))
    if copy and copy.get("replica_id"):
        replica_state = {
            "destroyed": "destroyed", "purged": "destroyed",
            "quarantined": "quarantined", "sealed": "sealed",
            "present": "present", "resurrected": "present",
            "offline_pending": "present", "pending": "present",
        }.get(state, state)
        db.execute("UPDATE access_replicas SET status=? WHERE id=?", (replica_state, copy["replica_id"]))


# ---------------------------------------------------------------------------
# Scene construction (the shared original block, two dispositions)
# ---------------------------------------------------------------------------

# Canonical fixture identities so JSON fixtures and tests speak the same names.
SCENE_DEFAULTS: Dict[str, Any] = {
    "scene": "access-erasure",
    "host": "api.example",
    "jia": "c-jia",
    "yi": "c-yi",
    "bing": "c-bing",
    "jia_epoch": 2,
    "bing_epoch": 3,
    "yi_host": "shop.example",
    "yi_epoch": 5,
    "block": "b1",
    "digest": "sha-a",
    "byte_count": 200,
    "gateway": "g1",
    "before_at": 21,
    "hold_start": 15,
    "hold_end": 18,
    "hold_refs": ["req-j-15", "req-j-16", "req-j-17", "req-j-18"],
    "hold_issuer": "issuer-court",
    "custodian": "custodian:court-vault",
}

# (id, seq, customer-key, at, request_ref, scope_tag, digest, bytes, payload)
SCENE_RECORDS = [
    ("rec-j10", 1, "jia", 10, "req-j-10", "billing", "sha-j10", 12, "JIA 10 /invoices"),
    ("rec-y11", 2, "yi", 11, "req-y-11", "catalog", "sha-y11", 10, "YI 11 /items"),
    ("rec-j12", 3, "jia", 12, "req-j-12", "billing", "sha-j12", 12, "JIA 12 /pay"),
    ("rec-j14", 4, "jia", 14, "req-j-14", "auth", "sha-j14", 11, "JIA 14 /login"),
    ("rec-j15a", 5, "jia", 15, "req-j-15", "case-4821", "sha-j15a", 13, "JIA 15 /subject?x=1"),
    ("rec-j15b", 6, "jia", 15, "req-j-15-other", "health", "sha-j15b", 9, "JIA 15 /healthz"),
    ("rec-j16", 7, "jia", 16, "req-j-16", "case-4821", "sha-j16", 13, "JIA 16 /subject?x=2"),
    ("rec-y16", 8, "yi", 16, "req-y-16", "catalog", "sha-y16", 10, "YI 16 /cart"),
    ("rec-j17", 9, "jia", 17, "req-j-17", "case-4821", "sha-j17", 13, "JIA 17 /subject?x=3"),
    ("rec-j18", 10, "jia", 18, "req-j-18", "case-4821", "sha-j18", 13, "JIA 18 /subject?x=4"),
    ("rec-j19", 11, "jia", 19, "req-j-19", "auth", "sha-j19", 11, "JIA 19 /token"),
    ("rec-y19", 12, "yi", 19, "req-y-19", "catalog", "sha-y19", 10, "YI 19 /checkout"),
    ("rec-j20", 13, "jia", 20, "req-j-20", "edge", "sha-j20", 11, "JIA 20 /cache"),
]


def build_scene(db, s: Dict[str, Any]) -> Dict[str, Any]:
    """Materialise the canonical shared-block scene.

    Parameters in ``s`` select the external truth and capabilities while the
    registered facts stay identical, which is what lets the same original block
    be exercised under both lawful dispositions.
    """
    ensure_schema(db)
    d = dict(SCENE_DEFAULTS)
    d.update({k: v for k, v in s.items() if k != "op"})
    prefix = d.get("id_prefix", "")
    bid = d["block"]

    def p(name: str) -> str:
        return f"{prefix}{name}"

    at0 = int(d.get("scene_at", 20))

    # --- ownership generations -------------------------------------------------
    db.execute("INSERT OR REPLACE INTO claims VALUES(?,?,?,?,?,?)",
               (d["host"], d["jia"], d["jia_epoch"], 200, "challenge-jia", "verified"))
    if d.get("include_transfer", True):
        db.execute("INSERT OR REPLACE INTO claims VALUES(?,?,?,?,?,?)",
                   (d["host"], d["bing"], d["bing_epoch"], 300, "challenge-bing", "verified"))
        # New holder's own later block must stay untouched.
        db.execute("INSERT OR REPLACE INTO access_blocks VALUES(?,?,?,?,?,?,?,?,?)",
                   (p("b2"), d["host"], d["bing_epoch"], d["bing"], 22, 30, "sha-c", 180, d["gateway"]))
        db.execute("INSERT OR REPLACE INTO storage_objects VALUES(?,?,?,?,?,?)",
                   ("west", f"access/{p('b2')}", "v3", "sha-c", 180, "present"))

    # --- the shared original block registration --------------------------------
    db.execute("INSERT OR REPLACE INTO access_blocks VALUES(?,?,?,?,?,?,?,?,?)",
               (bid, d["host"], d["jia_epoch"], "shared", 10, 20, d["digest"], d["byte_count"], d["gateway"]))

    for rid, seq, ckey, at, ref, tag, rdgst, bytes_n, payload in SCENE_RECORDS:
        customer = d[ckey]
        host = d["yi_host"] if ckey == "yi" else d["host"]
        epoch = d["yi_epoch"] if ckey == "yi" else d["jia_epoch"]
        db.execute("INSERT OR REPLACE INTO access_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                   (p(rid), bid, seq, customer, host, epoch, at, ref, tag, rdgst, bytes_n, payload))

    # --- trusted issuer + preservation notice ----------------------------------
    db.execute("INSERT OR REPLACE INTO hold_issuers VALUES(?,?,?,?)",
               (d["hold_issuer"], "Judicial Authority", "court", 1))
    if d.get("include_hold", True):
        arrived = int(d.get("hold_arrived_at", 23))
        issued = int(d.get("hold_issued_at", 22))
        db.execute("INSERT OR REPLACE INTO hold_notices_rich "
                   "(id,customer,host,claim_epoch,start_at,end_at,request_refs,scope_tag,case_ref,"
                   "cause,issuer,issued_at,arrived_at,valid_until,claimed_early,status,validation) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (p("h1"), d["jia"], d["host"], d["jia_epoch"], d["hold_start"], d["hold_end"],
                    _j(d["hold_refs"]), "case-4821", "CASE-4821",
                    "Preserve specific subject access requests", d["hold_issuer"],
                    issued, arrived, d.get("hold_valid_until"), 1 if arrived > issued else 0,
                    "received", "pending_validation"))
        # Legacy notice row kept for the archive/status surface.
        db.execute("INSERT OR REPLACE INTO hold_notices VALUES(?,?,?,?,?,?,?)",
                   (p("h1"), d["jia"], d["host"], d["hold_start"], d["hold_end"], issued, "active"))

    # --- erasure ticket already centrally acked (the false one-bit state) ------
    db.execute("INSERT OR REPLACE INTO erasure_tickets VALUES(?,?,?,?,?)",
               (p("e1"), d["jia"], d["host"], d["before_at"], "deleted"))

    # --- object versions + legacy replica ledger -------------------------------
    # The scene in the brief fixes west/current=v1 and east/current=v2 (the
    # latter's destroy receipt was lost).  west v0 is an old version that must
    # also be shredded.  All rows share the original sha-a digest.
    object_rows = [
        ("west", f"access/{bid}", "v0", d["digest"], d["byte_count"], "present", "cp-west-v0", "copy-west-v0"),
        ("west", f"access/{bid}", "v1", d["digest"], d["byte_count"], "present", "cp-west-v1", "copy-west"),
        ("east", f"access/{bid}", "v2", d["digest"], d["byte_count"], "present", "cp-east-v2", "copy-east"),
    ]
    for site, key, ver, dgst, size, state, cpid, repid in object_rows:
        db.execute("INSERT OR REPLACE INTO storage_objects VALUES(?,?,?,?,?,?)",
                   (site, key, ver, dgst, size, state))
        db.execute("INSERT OR REPLACE INTO access_replicas VALUES(?,?,?,?,?,?,?)",
                   (p(repid), bid, site, key, ver, dgst, "present"))
        db.execute("INSERT OR REPLACE INTO byte_copies "
                   "(id,block_id,replica_id,kind,location,object_key,version,digest,byte_count,"
                   "covers,record_ids,state,reachable,responsible,command_id,evidence) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (p(cpid), bid, p(repid), "object", site, key, ver, dgst, size,
                    "whole_block", None, "present", 1, f"object-owner:{site}", None, _j([])))

    # The east v2 destroy was sent and externally committed, but the receipt
    # was lost.  The command stays unacked until reconciliation recognises it.
    east_truth = d.get("east_truth", "destroyed_lost_ack")
    if east_truth == "destroyed_lost_ack":
        db.execute("UPDATE storage_objects SET physical_state='destroyed' WHERE site='east' AND object_key=? AND version='v2'",
                   (f"access/{bid}",))
        db.execute("UPDATE byte_copies SET state='destroyed', command_id=? WHERE id=?",
                   (p("cmd-east"), p("cp-east-v2")))
        db.execute("INSERT OR REPLACE INTO external_commands VALUES(?,?,?,?,?,?,?,?,?)",
                   (p("cmd-east"), f"idem-east-v2-{bid}", p("cp-east-v2"), "destroy",
                    _j({"site": "east", "object_key": f"access/{bid}", "version": "v2"}),
                    "unacked", 21, None, "connection_lost_after_commit"))
        _add_evidence(db, p("cp-east-v2"), {"channel": "send", "kind": "command_unacked", "at": 21,
                                            "command_id": p("cmd-east")})
    elif east_truth == "present_unknown":
        db.execute("INSERT OR REPLACE INTO external_commands VALUES(?,?,?,?,?,?,?,?,?)",
                   (p("cmd-east"), f"idem-east-v2-{bid}", p("cp-east-v2"), "destroy",
                    _j({"site": "east", "object_key": f"access/{bid}", "version": "v2"}),
                    "unacked", 21, None, "connection_lost_before_outcome"))
        db.execute("UPDATE byte_copies SET command_id=? WHERE id=?", (p("cmd-east"), p("cp-east-v2")))

    # --- gateway unarchived offline cache segment ------------------------------
    gw_records = [p("rec-j20"), p("rec-y19")]
    db.execute("INSERT OR REPLACE INTO external_assets "
               "(kind,location,object_key,version,digest,byte_count,state,reachable,attestation,reported_at) "
               "VALUES(?,?,?,?,?,?,?,?,?,?)",
               ("gateway_cache", d["gateway"], f"cache/{p('seg-g1')}", "seg-1", "sha-g1", 40,
                "present", 0, None, None))
    db.execute("INSERT OR REPLACE INTO byte_copies "
               "(id,block_id,replica_id,kind,location,object_key,version,digest,byte_count,"
               "covers,record_ids,state,reachable,responsible,command_id,evidence) "
               "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (p("cp-gw"), bid, None, "gateway_cache", d["gateway"], f"cache/{p('seg-g1')}", "seg-1",
                "sha-g1", 40, "cache_segment", _j(gw_records), "offline_pending", 0,
                f"gateway-ops:{d['gateway']}", None, _j([])))

    # --- backup copy -----------------------------------------------------------
    db.execute("INSERT OR REPLACE INTO external_assets "
               "(kind,location,object_key,version,digest,byte_count,state,reachable,attestation,reported_at) "
               "VALUES(?,?,?,?,?,?,?,?,?,?)",
               ("backup", "backup-vault", f"backup/{bid}", "snap-1", d["digest"], d["byte_count"],
                "retained", 1, None, None))
    db.execute("INSERT OR REPLACE INTO byte_copies "
               "(id,block_id,replica_id,kind,location,object_key,version,digest,byte_count,"
               "covers,record_ids,state,reachable,responsible,command_id,evidence) "
               "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (p("cp-bak"), bid, None, "backup", "backup-vault", f"backup/{bid}", "snap-1",
                d["digest"], d["byte_count"], "whole_block", None, "present", 1,
                "backup-ops:backup-vault", None, _j([])))

    # --- the already-issued false complete-deletion proof ----------------------
    if d.get("include_false_proof", True):
        body = {
            "ticket_id": p("e1"), "customer": d["jia"], "conclusion": "deleted_complete",
            "basis": "central_ack", "issued_at": 24,
            "claim": "all copies deleted",
        }
        db.execute("INSERT OR REPLACE INTO compliance_docs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                   (p("proof-central"), p("proof-central"), "deletion_proof", d["jia"], p("e1"),
                    None, 1, 24, "deleted_complete", _j(body), digest_bytes(canonical(body)), "delivered"))

    return {"decision": "scene_built", "block": bid, "ticket_id": p("e1"),
            "notice_id": p("h1"), "false_proof_id": p("proof-central"),
            "customer_jia": d["jia"], "customer_yi": d["yi"], "holder_bing": d["bing"]}


# ---------------------------------------------------------------------------
# Issuer / notice / release verification
# ---------------------------------------------------------------------------

def verify_notice(db, notice_id: str) -> Dict[str, Any]:
    n = one(db, "SELECT * FROM hold_notices_rich WHERE id=?", (notice_id,))
    if not n:
        return {"decision": "unknown_notice"}
    issuer = one(db, "SELECT * FROM hold_issuers WHERE id=?", (n["issuer"],))
    problems: List[str] = []
    if not issuer or not issuer["trusted"]:
        problems.append("unverified_issuer")
    if not n["case_ref"]:
        problems.append("missing_case_scope")
    # Arrival is what makes a notice enforceable against a live operator.
    if n["arrived_at"] is None:
        problems.append("no_arrival_time")
    validation = "valid" if not problems else "invalid:" + ",".join(problems)
    status = "effective" if not problems else "rejected"
    db.execute("UPDATE hold_notices_rich SET validation=?, status=? WHERE id=?", (validation, status, notice_id))
    return {"decision": "notice_verified" if not problems else "notice_rejected",
            "notice_id": notice_id, "validation": validation, "problems": problems}


def hold_active_at(notice: Dict[str, Any], t: int, db=None) -> bool:
    """True iff the notice actually bound the operator at instant ``t``.

    Effectivity starts at *actual arrival*, never at the claimed issue time, so
    a late or back-dated notice cannot be retroactively valid at deletion time.
    A verified release ends the duty at its release time.
    """
    if notice.get("status") == "rejected" or str(notice.get("validation", "")).startswith("invalid"):
        return False
    arrived = notice.get("arrived_at")
    if arrived is None or t < arrived:
        return False
    if notice.get("valid_until") is not None and t > notice["valid_until"]:
        return False
    db = db or getattr(_DB, "db", None)
    if db is not None:
        rel = one(db, "SELECT * FROM hold_releases WHERE notice_id=? AND verified=1 "
                      "ORDER BY released_at DESC LIMIT 1", (notice["id"],))
        if rel and rel["released_at"] is not None and t >= rel["released_at"]:
            return False
    return True


# Thread-local handle so the predicate can read releases without threading db
# through every matcher.  _active_notices() binds it on each evaluation.
import threading
_DB = threading.local()


def _active_notices(db, customer: str, host: str, epoch: int, at: int) -> List[Dict[str, Any]]:
    _DB.db = db
    out = []
    for n in rows(db, "SELECT * FROM hold_notices_rich WHERE customer=? AND host=? AND claim_epoch=?",
                  (customer, host, epoch)):
        if verify_notice(db, n["id"])["decision"] != "notice_verified":
            continue
        if hold_active_at(n, at, db):
            out.append(n)
    return out


def notice_selects_record(notice: Dict[str, Any], rec: Dict[str, Any]) -> bool:
    if not (notice["start_at"] <= rec["at"] <= notice["end_at"]):
        return False
    refs = set(_loads(notice["request_refs"], []) or [])
    if refs:
        return rec.get("request_ref") in refs
    tag = notice.get("scope_tag")
    if tag:
        return rec.get("scope_tag") == tag
    return True


# ---------------------------------------------------------------------------
# Scope resolution
# ---------------------------------------------------------------------------

def resolve_scope(db, ticket_id: str, at: Optional[int] = None,
                  claim_epoch: Optional[int] = None,
                  byte_digest: Optional[str] = None) -> Dict[str, Any]:
    """Resolve the exact deletion scope.

    Conjunction of customer + domain ownership generation + log time + digest.
    Returns blocks, records and every known copy, plus the ownership guard that
    excludes a later holder's epoch.
    """
    ensure_schema(db)
    ticket = one(db, "SELECT * FROM erasure_tickets WHERE id=?", (ticket_id,))
    if not ticket:
        return {"decision": "unknown_ticket"}
    customer, host, before_at = ticket["customer"], ticket["host"], ticket["before_at"]
    at = int(at if at is not None else before_at)

    # The request may pin the ownership generation explicitly; otherwise use
    # the generation carried by matching blocks.  Never infer "current claim",
    # because the current claim can already belong to the new holder.
    blocks = rows(db, "SELECT * FROM access_blocks WHERE host=?", (host,))
    scoped_blocks: List[Dict[str, Any]] = []
    excluded_epochs: List[Dict[str, Any]] = []
    for b in blocks:
        epoch_ok = claim_epoch is None or b["claim_epoch"] == claim_epoch
        # A block participates if its window could contain pre-cutover records.
        time_ok = b["start_at"] < before_at
        digest_ok = byte_digest is None or b["byte_digest"] == byte_digest
        customer_ok = b["customer"] in (customer, "shared")
        if epoch_ok and time_ok and digest_ok and customer_ok:
            scoped_blocks.append(b)
        else:
            excluded_epochs.append({"block_id": b["id"], "claim_epoch": b["claim_epoch"],
                                     "customer": b["customer"], "reason":
                                     "ownership_epoch" if not epoch_ok else
                                     ("digest" if not digest_ok else
                                      ("time_window" if not time_ok else "customer"))})

    block_ids = [b["id"] for b in scoped_blocks]
    epochs = sorted({b["claim_epoch"] for b in scoped_blocks})
    resolved_epoch = claim_epoch if claim_epoch is not None else (epochs[0] if len(epochs) == 1 else None)
    records: List[Dict[str, Any]] = []
    if block_ids:
        q = ",".join("?" * len(block_ids))
        records = rows(db, f"SELECT * FROM access_records WHERE block_id IN ({q}) ORDER BY seq", block_ids)

    jia_records = [r for r in records if r["customer"] == customer and r["at"] < before_at]
    other_records = [r for r in records if r["customer"] != customer]

    # Effective holds as of resolution instant partition the customer records.
    held: List[Dict[str, Any]] = []
    hold_hits: List[Dict[str, Any]] = []
    for epoch in {b["claim_epoch"] for b in scoped_blocks}:
        for n in _active_notices(db, customer, host, epoch, at):
            hits = [r for r in jia_records if r["claim_epoch"] == epoch and notice_selects_record(n, r)]
            if hits:
                hold_hits.append({"notice_id": n["id"], "case_ref": n["case_ref"],
                                  "record_ids": [r["id"] for r in hits]})
                held.extend(hits)
    held_ids = {r["id"] for r in held}
    deletable = [r for r in jia_records if r["id"] not in held_ids]

    copies: List[Dict[str, Any]] = []
    if block_ids:
        q = ",".join("?" * len(block_ids))
        copies = rows(db, f"SELECT * FROM byte_copies WHERE block_id IN ({q})", block_ids)

    scope = {
        "ticket_id": ticket_id,
        "customer": customer,
        "host": host,
        "before_at": before_at,
        "at": at,
        "claim_epoch": resolved_epoch,
        "claim_epochs": epochs,
        "digests": sorted({b["byte_digest"] for b in scoped_blocks}),
        "blocks": [b["id"] for b in scoped_blocks],
        "excluded": excluded_epochs,
        "customer_record_ids": [r["id"] for r in jia_records],
        "deletable_record_ids": [r["id"] for r in deletable],
        "held_record_ids": sorted(held_ids),
        "other_tenant_records": [{"customer": r["customer"], "record_id": r["id"]} for r in other_records],
        "hold_hits": hold_hits,
        "copy_ids": [c["id"] for c in copies],
        "original_digest": "sha-a" if any(b["byte_digest"] == "sha-a" for b in scoped_blocks) else None,
        "original_byte_count": sum(b["byte_count"] for b in scoped_blocks),
    }
    db.execute("INSERT OR REPLACE INTO scope_resolutions VALUES(?,?,?)",
               (ticket_id, at, _j(scope)))
    return {"decision": "scope_resolved", **scope}


# ---------------------------------------------------------------------------
# External observation / reconciliation ("认回")
# ---------------------------------------------------------------------------

def _observe_object(db, copy: Dict[str, Any], at: int) -> Dict[str, Any]:
    obj = one(db, "SELECT * FROM storage_objects WHERE site=? AND object_key=? AND version=?",
              (copy["location"], copy["object_key"], copy["version"]))
    if not obj:
        observed = {"channel": "inspect", "state": "missing", "digest": None}
    else:
        observed = {"channel": "inspect", "state": obj["physical_state"], "digest": obj["byte_digest"],
                    "byte_count": obj["byte_count"]}
    observed["at"] = at
    return observed


def _observe_asset(db, copy: Dict[str, Any], at: int) -> Dict[str, Any]:
    asset = one(db, "SELECT * FROM external_assets WHERE kind=? AND location=? AND object_key=? AND version=?",
                (copy["kind"], copy["location"], copy["object_key"], copy["version"]))
    if not asset:
        return {"channel": copy["kind"], "state": "missing", "digest": None, "at": at}
    return {"channel": copy["kind"], "state": asset["state"], "digest": asset["digest"],
            "reachable": asset["reachable"], "attestation": asset["attestation"], "at": at}


# These copy kinds are versions in the object store plane (storage_objects);
# gateway caches and backups live in the external_assets plane.
OBJECT_PLANE_KINDS = {"object", "hold_fragment", "repacked_tenant_object",
                      "repacked_requester_object"}


def _observe_by_plane(db, copy: Dict[str, Any], at: int) -> Dict[str, Any]:
    if copy["kind"] in OBJECT_PLANE_KINDS:
        return _observe_object(db, copy, at)
    return _observe_asset(db, copy, at)


def reconcile(db, s: Dict[str, Any]) -> Dict[str, Any]:
    """Observe every external copy and adopt committed destructions.

    Never re-sends a destroy.  An unacked command whose target is observed
    destroyed/purged is recognised as already committed.  A target still present
    is reported for a hold-aware decision.
    """
    ensure_schema(db)
    at = int(s.get("at", 30))
    ticket_id = s.get("ticket_id")
    copy_id = s.get("copy_id")
    if copy_id:
        copies = [one(db, "SELECT * FROM byte_copies WHERE id=?", (copy_id,))]
        copies = [c for c in copies if c]
    elif ticket_id:
        scope = resolve_scope(db, ticket_id, at)
        copies = rows(db, "SELECT * FROM byte_copies WHERE id IN (%s)" %
                      ",".join("?" * len(scope["copy_ids"])), scope["copy_ids"]) if scope["copy_ids"] else []
    else:
        copies = rows(db, "SELECT * FROM byte_copies")

    recognised, present, unavailable, mismatched = [], [], [], []
    for cp in copies:
        obs = _observe_by_plane(db, cp, at)
        _add_evidence(db, cp["id"], {"kind": "observation", **obs})

        if obs.get("digest") and cp["digest"] and obs["digest"] != cp["digest"] and obs["state"] == "present":
            mismatched.append({"copy_id": cp["id"], "registered": cp["digest"], "observed": obs["digest"]})

        unacked = one(db, "SELECT * FROM external_commands WHERE copy_id=? AND state='unacked' ORDER BY issued_at",
                      (cp["id"],))
        if obs["state"] in ("destroyed", "purged", "missing"):
            if unacked:
                db.execute("UPDATE external_commands SET state='confirmed_recognized', decided_at=?, detail=? WHERE id=?",
                           (at, "committed_outcome_recognised_without_resend", unacked["id"]))
            new_state = "destroyed" if obs["state"] != "missing" else "missing"
            if cp["state"] not in ("quarantined", "sealed"):
                _set_copy_state(db, cp["id"], new_state, at)
            recognised.append({"copy_id": cp["id"], "state": obs["state"],
                               "command_recognised": unacked["id"] if unacked else None,
                               "resent": False})
        elif obs["state"] == "present":
            if not obs.get("reachable", 1):
                unavailable.append({"copy_id": cp["id"], "reason": "channel_unreachable"})
                if cp["state"] != "offline_pending":
                    _set_copy_state(db, cp["id"], "offline_pending", at)
            else:
                present.append({"copy_id": cp["id"], "digest": obs.get("digest")})
                if cp["state"] in ("destroyed",):
                    # Object version resurrection: ledger said destroyed, real
                    # store says present.  Surface loudly instead of hiding it.
                    _set_copy_state(db, cp["id"], "resurrected", at,
                                    {"kind": "resurrection_detected", "digest": obs.get("digest")})
                    present[-1]["resurrected"] = True
        elif obs["state"] in ("quarantined", "sealed"):
            recognised.append({"copy_id": cp["id"], "state": obs["state"], "preserved": True})
        else:
            present.append({"copy_id": cp["id"], "state": obs["state"]})

    return {"decision": "reconciled", "at": at, "recognised_destroyed": recognised,
            "still_present": present, "offline": unavailable, "digest_mismatch": mismatched,
            "resent_commands": 0}


def recover_copy(db, copy_id: str, at: int, hold_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Safe recovery for one uncertain copy: observe first, then decide.

    If the bytes are already gone, adopt that.  If present and a valid hold now
    covers them, preserve (seal/quarantine) rather than destroy.  Only a present
    hold-free copy receives an idempotent destroy command.
    """
    cp = one(db, "SELECT * FROM byte_copies WHERE id=?", (copy_id,))
    if not cp:
        return {"decision": "unknown_copy"}
    rec = reconcile(db, {"copy_id": copy_id, "at": at})
    if any(x["copy_id"] == copy_id for x in rec["recognised_destroyed"]):
        return {"decision": "recognised_existing_destruction", "copy_id": copy_id, "resent": False}
    if any(x["copy_id"] == copy_id for x in rec["offline"]):
        return {"decision": "channel_offline_pending_report", "copy_id": copy_id}

    holds = hold_context or {}
    if holds.get("active_hold"):
        mode = holds.get("mode", "seal")
        if mode == "quarantine":
            return quarantine_copy(db, copy_id, at, holds.get("fragment_id"))
        return {"decision": "held_preserved_not_destroyed", "copy_id": copy_id,
                "notice_id": holds.get("notice_id")}

    return issue_destroy(db, copy_id, at)


def issue_destroy(db, copy_id: str, at: int, outcome: str = "acked",
                  action: str = "destroy", idem_suffix: Optional[str] = None) -> Dict[str, Any]:
    """Issue an idempotent destroy/purge against the external plane.

    ``outcome='committed_lost_ack'`` models a commit whose acknowledgement is
    lost; the external plane is mutated but the command stays ``unacked`` so a
    later reconcile must recognise it.  ``idem_suffix`` identifies a *new
    incarnation* of a target (for example after a version resurrection): the
    old acknowledged command must not be reused for restored bytes.
    """
    ensure_schema(db)
    cp = one(db, "SELECT * FROM byte_copies WHERE id=?", (copy_id,))
    if not cp:
        return {"decision": "unknown_copy"}
    idem = f"{action}:{copy_id}" + (f":{idem_suffix}" if idem_suffix else "")
    existing = one(db, "SELECT * FROM external_commands WHERE idem_key=?", (idem,))
    if existing:
        # Never blindly issue a second external command for the same intent.
        return {"decision": "command_already_known", "command_id": existing["id"],
                "state": existing["state"], "resent": False}
    cmd_id = f"cmd-{action}-{copy_id}"
    target = _j({"kind": cp["kind"], "location": cp["location"], "object_key": cp["object_key"],
                 "version": cp["version"]})
    committed = outcome in ("acked", "committed_lost_ack")
    db.execute("INSERT INTO external_commands VALUES(?,?,?,?,?,?,?,?,?)",
               (cmd_id, idem, copy_id, action, target,
                "unacked" if outcome == "committed_lost_ack" else ("issued" if not committed else "acked"),
                at, at if outcome == "acked" else None, outcome))
    db.execute("UPDATE byte_copies SET command_id=? WHERE id=?", (cmd_id, copy_id))

    if committed:
        _external_mutate_destroy(db, cp, at)
    if outcome == "acked":
        db.execute("UPDATE external_commands SET state='acked', decided_at=? WHERE id=?", (at, cmd_id))
        _set_copy_state(db, copy_id, "purged" if cp["kind"] == "gateway_cache" else "destroyed", at,
                        {"kind": "destroy_acked", "command_id": cmd_id})
        return {"decision": "destroyed", "copy_id": copy_id, "command_id": cmd_id, "resent": False}
    if outcome == "committed_lost_ack":
        _set_copy_state(db, copy_id, "destroyed", at,
                        {"kind": "destroy_committed_ack_lost", "command_id": cmd_id})
        return {"decision": "ack_lost", "copy_id": copy_id, "command_id": cmd_id, "resent": False}
    # connection failure before any commit
    db.execute("UPDATE external_commands SET state='send_failed', decided_at=? WHERE id=?", (at, cmd_id))
    return {"decision": "connection_error", "copy_id": copy_id, "command_id": cmd_id}


def _external_mutate_destroy(db, cp: Dict[str, Any], at: int) -> None:
    if cp["kind"] in OBJECT_PLANE_KINDS:
        db.execute("UPDATE storage_objects SET physical_state='destroyed' WHERE site=? AND object_key=? AND version=?",
                   (cp["location"], cp["object_key"], cp["version"]))
    else:
        destroyed_state = "purged" if cp["kind"] == "gateway_cache" else "destroyed"
        db.execute("UPDATE external_assets SET state=? WHERE kind=? AND location=? AND object_key=? AND version=?",
                   (destroyed_state, cp["kind"], cp["location"], cp["object_key"], cp["version"]))


# ---------------------------------------------------------------------------
# Gateway offline supplementary report
# ---------------------------------------------------------------------------

def gateway_report(db, s: Dict[str, Any]) -> Dict[str, Any]:
    """Adopt a late gateway report; never back-dates verification.

    The gateway reports the segment's true state and when it was purged.  The
    operator verifies at arrival (``at``) but may record the gateway-asserted
    purge time separately.
    """
    ensure_schema(db)
    copy_id = s["copy_id"]
    at = int(s["at"])
    cp = one(db, "SELECT * FROM byte_copies WHERE id=?", (copy_id,))
    if not cp:
        return {"decision": "unknown_copy"}
    reported_state = s.get("state", "purged")
    digest = s.get("digest", cp["digest"])
    if digest != cp["digest"]:
        return {"decision": "report_digest_mismatch", "copy_id": copy_id,
                "registered": cp["digest"], "reported": digest}
    db.execute("UPDATE external_assets SET state=?, reachable=1, digest=?, reported_at=? "
               "WHERE kind='gateway_cache' AND location=? AND object_key=? AND version=?",
               (reported_state, digest, at, cp["location"], cp["object_key"], cp["version"]))
    if reported_state == "purged":
        _set_copy_state(db, copy_id, "purged", at,
                        {"kind": "gateway_supplementary_report", "reported_at": at,
                         "gateway_purged_at": s.get("purged_at"), "report_id": s.get("report_id")})
        return {"decision": "gateway_report_adopted_purged", "copy_id": copy_id, "verified_at": at}
    _set_copy_state(db, copy_id, "resurrected" if cp["state"] == "purged" else "present", at,
                    {"kind": "gateway_report_present", "reported_at": at})
    return {"decision": "gateway_report_adopted_present", "copy_id": copy_id, "verified_at": at}


# ---------------------------------------------------------------------------
# Split disposition: recompose independent objects, minimise hold, shred rest
# ---------------------------------------------------------------------------

def _put_repacked_object(db, copy_id: str, block_id: str, kind: str, site: str, key: str,
                         records_: List[Dict[str, Any]], at: int, responsible: str,
                         extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    dgst = digest_records(records_)
    size = sum(int(r.get("byte_count") or 0) for r in records_)
    version = "v1"
    db.execute("INSERT OR REPLACE INTO storage_objects VALUES(?,?,?,?,?,?)",
               (site, key, version, dgst, size, "present"))
    db.execute("INSERT OR REPLACE INTO byte_copies "
               "(id,block_id,replica_id,kind,location,object_key,version,digest,byte_count,"
               "covers,record_ids,state,reachable,responsible,command_id,evidence) "
               "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (copy_id, block_id, None, kind, site, key, version, dgst, size, kind,
                _j([r["id"] for r in records_]), "present", 1, responsible, None, _j([])))
    _add_evidence(db, copy_id, {"kind": "repacked_object_created", "at": at, "digest": dgst,
                                 "record_count": len(records_)})
    # Extra verification duty created by migration: immediately re-inspect and
    # pin the observed digest against the computed one.
    obs = _observe_object(db, one(db, "SELECT * FROM byte_copies WHERE id=?", (copy_id,)), at)
    verified = obs.get("digest") == dgst and obs.get("state") == "present"
    _add_evidence(db, copy_id, {"kind": "new_version_digest_verified", "at": at, "verified": verified})
    return {"copy_id": copy_id, "digest": dgst, "byte_count": size, "verified": verified}


def disposition_split(db, s: Dict[str, Any]) -> Dict[str, Any]:
    """Lawful disposition A: split, minimise preservation, destroy originals."""
    ensure_schema(db)
    ticket_id = s["ticket_id"]
    at = int(s.get("at", 30))
    scope = resolve_scope(db, ticket_id, at)
    if scope["decision"] == "unknown_ticket":
        return scope
    if s.get("splittable") is False:
        return {"decision": "split_unavailable",
                "reason": s.get("split_reason", "device_cannot_safely_split_block"),
                "safe_alternative": "quarantine"}

    block_id = scope["blocks"][0]
    all_records = rows(db, "SELECT * FROM access_records WHERE block_id=?", (block_id,))
    by_id = {r["id"]: r for r in all_records}
    deletable = [by_id[i] for i in scope["deletable_record_ids"] if i in by_id]
    held = [by_id[i] for i in scope["held_record_ids"] if i in by_id]
    other_ids = [o["record_id"] for o in scope["other_tenant_records"]]
    other = [by_id[i] for i in other_ids if i in by_id]
    prefix = s.get("id_prefix", "")
    jia = scope["customer"]

    # Account for every record exactly once before shredding anything.
    accounted = {r["id"] for r in deletable} | {r["id"] for r in held} | {r["id"] for r in other}
    if accounted != {r["id"] for r in all_records}:
        return {"decision": "split_accounting_gap",
                "missing": sorted({r["id"] for r in all_records} - accounted)}

    created: Dict[str, Any] = {}

    # 1) Other tenant gets an independent retained object (never disclosed or
    #    destroyed by the requester's workflow).
    if other:
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for r in other:
            groups.setdefault(r["customer"], []).append(r)
        for cust, recs in groups.items():
            cid = f"{prefix}copy-yi-{_slug(cust)}"
            created[cust] = _put_repacked_object(
                db, cid, block_id, "repacked_tenant_object", "repack",
                f"tenant/{_slug(cust)}/{block_id}", recs, at, f"data-owner:{cust}")

    # 2) Seal only the minimal held fragment first, so evidence survives even
    #    though the original block is about to be shredded.
    fragment_id = None
    if held and scope["hold_hits"]:
        hit = scope["hold_hits"][0]
        notice_id = hit["notice_id"]
        fragment_id = f"{prefix}frag-{notice_id}"
        fr = _put_repacked_object(
            db, f"{prefix}copy-frag-{notice_id}", block_id, "hold_fragment", "hold-vault",
            f"hold/{notice_id}/{block_id}.min", held, at, SCENE_DEFAULTS["custodian"])
        db.execute("INSERT OR REPLACE INTO hold_fragments "
                   "(id,notice_id,block_id,copy_id,minimized,record_ids,digest,byte_count,vault,state,"
                   "sealed_at,released_at,destroyed_at,release_id,device_cert_id,evidence) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (fragment_id, notice_id, block_id, fr["copy_id"], 1,
                    _j([r["id"] for r in held]), fr["digest"], fr["byte_count"], "hold-vault",
                    "sealed", at, None, None, None, None, _j([fr])))
        _set_copy_state(db, fr["copy_id"], "sealed", at)
        db.execute("UPDATE storage_objects SET physical_state='sealed' WHERE site='hold-vault' "
                   "AND object_key=? AND version='v1'", (f"hold/{notice_id}/{block_id}.min",))
        created["hold_fragment"] = {"fragment_id": fragment_id, **fr}

    # 3) Recompose the unprotected requester records into an independent object,
    #    then destroy that migration object too (these bytes are all deletable).
    if deletable:
        jr = _put_repacked_object(
            db, f"{prefix}copy-jia-residual", block_id, "repacked_requester_object", "repack",
            f"requester/{_slug(jia)}/{block_id}.residual", deletable, at, f"erasure-ops:{jia}")
        created["jia_residual"] = jr
        issue_destroy(db, jr["copy_id"], at, outcome="acked")

    # 4) Reconcile and destroy every original / old-version / backup copy.
    rec = reconcile(db, {"ticket_id": ticket_id, "at": at})
    destroyed_copies, pending_copies = [], []
    for cp in rows(db, "SELECT * FROM byte_copies WHERE block_id=?", (block_id,)):
        if cp["id"] in {f"{prefix}copy-frag-{h['notice_id']}" for h in scope["hold_hits"]}:
            continue
        if cp["kind"] == "hold_fragment" or cp["state"] == "sealed":
            continue
        if cp["kind"] == "repacked_tenant_object":
            continue
        result = recover_copy(db, cp["id"], at)
        if result["decision"] in ("destroyed", "recognised_existing_destruction", "command_already_known"):
            destroyed_copies.append(cp["id"])
        elif result["decision"] == "channel_offline_pending_report":
            pending_copies.append(cp["id"])
        else:
            destroyed_copies.append(cp["id"])

    # 5) Final verification pass over object versions.
    verification = verify_copies(db, ticket_id, at + 1)

    conclusion = "partially_deleted_legal_hold_retained" if held else "deleted_complete"
    proof = issue_segmented_proof(
        db, {"id": s.get("proof_id", f"{prefix}proof-split"), "ticket_id": ticket_id, "at": at + 2,
             "conclusion": conclusion, "disposition": "split", "scope": scope,
             "verification": verification, "created": created,
             "destroyed_copies": destroyed_copies, "pending_copies": pending_copies})
    preservation = issue_preservation_schedule(
        db, {"id": s.get("schedule_id", f"{prefix}hold-list-1"), "ticket_id": ticket_id,
             "at": at + 2, "scope": scope, "fragment_id": fragment_id})
    return {"decision": "split_disposition_complete", "conclusion": conclusion,
            "proof_id": proof["doc_id"], "preservation_id": preservation["doc_id"],
            "fragment_id": fragment_id, "destroyed_copies": destroyed_copies,
            "pending_copies": pending_copies, "created": created, "verification": verification}


def _slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in str(value))


# ---------------------------------------------------------------------------
# Quarantine disposition: whole block to restricted vault, no false completion
# ---------------------------------------------------------------------------

def quarantine_copy(db, copy_id: str, at: int, fragment_id: Optional[str] = None,
                    reason: str = "device_cannot_safely_split_block") -> Dict[str, Any]:
    cp = one(db, "SELECT * FROM byte_copies WHERE id=?", (copy_id,))
    if not cp:
        return {"decision": "unknown_copy"}
    # Move the external object into a restricted vault state.  We model this as
    # an in-place lockdown plus a vault marker; ordinary access is revoked.
    if cp["kind"] == "object":
        db.execute("UPDATE storage_objects SET physical_state='quarantined' WHERE site=? AND object_key=? AND version=?",
                   (cp["location"], cp["object_key"], cp["version"]))
    else:
        db.execute("UPDATE external_assets SET state='quarantined' WHERE kind=? AND location=? AND object_key=? AND version=?",
                   (cp["kind"], cp["location"], cp["object_key"], cp["version"]))
    _set_copy_state(db, copy_id, "quarantined", at,
                    {"kind": "quarantined_restricted_vault", "reason": reason,
                     "vault": "restricted-preservation-vault", "ordinary_access": "revoked"})
    db.execute("UPDATE byte_copies SET responsible=? WHERE id=?", (SCENE_DEFAULTS["custodian"], copy_id))
    return {"decision": "quarantined", "copy_id": copy_id, "vault": "restricted-preservation-vault"}


def ordinary_access(db, s: Dict[str, Any]) -> Dict[str, Any]:
    """Simulate an ordinary read; quarantined/sealed bytes must be denied."""
    copy_id = s.get("copy_id")
    cp = one(db, "SELECT * FROM byte_copies WHERE id=?", (copy_id,)) if copy_id else None
    if not cp:
        # Also allow addressing the object triple directly.
        obj = one(db, "SELECT physical_state FROM storage_objects WHERE site=? AND object_key=? AND version=?",
                  (s.get("site"), s.get("object_key"), s.get("version")))
        if not obj:
            return {"decision": "missing"}
        if obj["physical_state"] in ("quarantined", "sealed", "destroyed"):
            return {"decision": "access_denied_restricted", "physical_state": obj["physical_state"]}
        return {"decision": "access_granted"}
    if cp["state"] in ("quarantined", "sealed"):
        return {"decision": "access_denied_restricted", "copy_id": copy_id, "state": cp["state"]}
    if cp["state"] == "destroyed":
        return {"decision": "missing", "copy_id": copy_id}
    return {"decision": "access_granted", "copy_id": copy_id}


def handle_revival(db, s: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve an object version that reappeared after being destroyed.

    Re-observes the copy, re-checks holds effective *now* (a late notice may
    have arrived while the bytes were gone), then either quarantines the
    resurrected whole block under the hold or destroys the new incarnation.
    Always appends a correction to the already-issued completion proof because
    the earlier "complete" statement was falsified at an observed instant.
    """
    ensure_schema(db)
    copy_id = s["copy_id"]
    at = int(s.get("at", 36))
    ticket_id = s.get("ticket_id")
    cp = one(db, "SELECT * FROM byte_copies WHERE id=?", (copy_id,))
    if not cp:
        return {"decision": "unknown_copy"}

    rec = reconcile(db, {"copy_id": copy_id, "at": at})
    revived = any(x.get("copy_id") == copy_id and x.get("resurrected") for x in rec["still_present"])
    obs = _observe_by_plane(db, cp, at)
    if obs["state"] != "present":
        return {"decision": "no_revival_present", "observed_state": obs["state"]}

    # Re-check currently effective holds for this ticket/customer.
    active_hold = None
    if ticket_id:
        scope = resolve_scope(db, ticket_id, at)
        if scope.get("hold_hits"):
            active_hold = scope["hold_hits"][0]
    if s.get("hold_notice_id"):
        active_hold = {"notice_id": s["hold_notice_id"]}

    correction_id = s.get("correction_id", f"corr-revival-{copy_id}")
    amends = s.get("amends_id")

    if active_hold:
        q = quarantine_copy(db, copy_id, at, reason="resurrected_version_subject_to_effective_hold")
        frag_id = s.get("fragment_id", f"frag-revival-{copy_id}")
        all_records = rows(db, "SELECT id FROM access_records WHERE block_id=?", (cp["block_id"],))
        db.execute("INSERT OR REPLACE INTO hold_fragments "
                   "(id,notice_id,block_id,copy_id,minimized,record_ids,digest,byte_count,vault,state,"
                   "sealed_at,released_at,destroyed_at,release_id,device_cert_id,evidence) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (frag_id, active_hold["notice_id"], cp["block_id"], copy_id, 0,
                    _j([r["id"] for r in all_records]), obs.get("digest") or cp["digest"],
                    cp["byte_count"], "restricted-preservation-vault", "quarantined", at,
                    None, None, None, None, _j({"resurrection": True})))
        if amends:
            append_correction(db, {"id": correction_id, "amends_id": amends, "at": at,
                                   "conclusion": "completion_proof_corrected_resurrected_and_preserved",
                                   "reason": "a destroyed object version reappeared and a hold is now effective",
                                   "corrected": {"copy_id": copy_id, "physical_state": "quarantined",
                                                 "fragment_id": frag_id}})
        return {"decision": "resurrection_quarantined_under_hold", "copy_id": copy_id,
                "fragment_id": frag_id, "notice_id": active_hold["notice_id"],
                "correction_id": correction_id if amends else None, "new_destroy_command_sent": False}

    # No hold: destroy the restored incarnation with a fresh idempotency key.
    suffix = s.get("incarnation", "revived-1")
    d = issue_destroy(db, copy_id, at, outcome=s.get("outcome", "acked"), idem_suffix=str(suffix))
    if amends:
        append_correction(db, {"id": correction_id, "amends_id": amends, "at": at,
                               "conclusion": "completion_proof_supplemented_redestroyed_revived_version",
                               "reason": "a version briefly reappeared and was destroyed again",
                               "corrected": {"copy_id": copy_id, "redestroy_result": d["decision"],
                                             "command_id": d.get("command_id")}})
    return {"decision": "resurrection_redestroyed", "copy_id": copy_id,
            "command_id": d.get("command_id"), "destroy_result": d["decision"],
            "correction_id": correction_id if amends else None}


def disposition_quarantine(db, s: Dict[str, Any]) -> Dict[str, Any]:
    """Lawful disposition B: quarantine whole block; never claim completion."""
    ensure_schema(db)
    ticket_id = s["ticket_id"]
    at = int(s.get("at", 30))
    scope = resolve_scope(db, ticket_id, at)
    if scope["decision"] == "unknown_ticket":
        return scope
    block_id = scope["blocks"][0]
    prefix = s.get("id_prefix", "")

    rec = reconcile(db, {"ticket_id": ticket_id, "at": at})

    # Choose the highest present, digest-matching whole-block object to
    # quarantine (the current version rather than a superseded old one).
    candidates = rows(db, "SELECT * FROM byte_copies WHERE block_id=? AND kind='object' "
                          "AND state IN ('present','resurrected')", (block_id,))

    def _version_key(cp):
        v = str(cp["version"] or "")
        digits = v.lstrip("vV")
        return (0, int(digits)) if digits.isdigit() else (1, v)

    survivor = None
    for cp in sorted(candidates, key=_version_key, reverse=True):
        obj = one(db, "SELECT * FROM storage_objects WHERE site=? AND object_key=? AND version=?",
                  (cp["location"], cp["object_key"], cp["version"]))
        if obj and obj["physical_state"] == "present" and obj["byte_digest"] == cp["digest"]:
            survivor = cp
            break
    if survivor is None:
        # Nothing intact to preserve: adopt reconciled destruction instead.
        return {"decision": "no_intact_copy_to_quarantine", "use": "split_or_complete",
                "reconcile": rec["decision"]}

    q = quarantine_copy(db, survivor["id"], at)
    all_records = rows(db, "SELECT * FROM access_records WHERE block_id=?", (block_id,))
    fragment_id = f"{prefix}frag-quarantine-{survivor['id']}"
    db.execute("INSERT OR REPLACE INTO hold_fragments "
               "(id,notice_id,block_id,copy_id,minimized,record_ids,digest,byte_count,vault,state,"
               "sealed_at,released_at,destroyed_at,release_id,device_cert_id,evidence) "
               "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (fragment_id, scope["hold_hits"][0]["notice_id"] if scope["hold_hits"] else None,
                block_id, survivor["id"], 0, _j([r["id"] for r in all_records]),
                survivor["digest"], survivor["byte_count"], "restricted-preservation-vault",
                "quarantined", at, None, None, None, None,
                _j({"note": "whole shared block retained because safe splitting is unavailable",
                    "contains_other_tenant_records": True})))

    # Destroy every redundant copy (other versions/sites/backup); keep survivor.
    destroyed_copies, pending_copies = [], []
    for cp in rows(db, "SELECT * FROM byte_copies WHERE block_id=?", (block_id,)):
        if cp["id"] == survivor["id"] or cp["state"] in ("quarantined", "sealed"):
            continue
        result = recover_copy(db, cp["id"], at)
        if result["decision"] == "channel_offline_pending_report":
            pending_copies.append(cp["id"])
        else:
            destroyed_copies.append(cp["id"])

    verification = verify_copies(db, ticket_id, at + 1)
    conclusion = "incomplete_quarantined_whole_block"
    proof = issue_segmented_proof(
        db, {"id": s.get("proof_id", f"{prefix}proof-quarantine"), "ticket_id": ticket_id, "at": at + 2,
             "conclusion": conclusion, "disposition": "quarantine", "scope": scope,
             "verification": verification, "quarantined_copy": survivor["id"],
             "fragment_id": fragment_id, "destroyed_copies": destroyed_copies,
             "pending_copies": pending_copies,
             "physical_deletion_complete": False})
    preservation = issue_preservation_schedule(
        db, {"id": s.get("schedule_id", f"{prefix}hold-list-q"), "ticket_id": ticket_id,
             "at": at + 2, "scope": scope, "fragment_id": fragment_id, "whole_block": True})
    return {"decision": "quarantine_disposition_complete", "conclusion": conclusion,
            "proof_id": proof["doc_id"], "preservation_id": preservation["doc_id"],
            "quarantined_copy": survivor["id"], "fragment_id": fragment_id,
            "destroyed_copies": destroyed_copies, "pending_copies": pending_copies,
            "physical_deletion_complete": False}


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_copies(db, ticket_id: str, at: int) -> Dict[str, Any]:
    scope = resolve_scope(db, ticket_id, at)
    results = []
    for cid in scope["copy_ids"]:
        cp = one(db, "SELECT * FROM byte_copies WHERE id=?", (cid,))
        if not cp:
            continue
        obs = _observe_by_plane(db, cp, at)
        results.append({"copy_id": cid, "ledger_state": cp["state"], "observed_state": obs["state"],
                        "digest": obs.get("digest"), "consistent":
                        _consistent(cp["state"], obs["state"])})
    return {"at": at, "copies": results,
            "all_destroyed_or_preserved": all(
                r["observed_state"] in ("destroyed", "purged", "missing", "quarantined", "sealed")
                for r in results)}


def _consistent(ledger: str, observed: str) -> bool:
    if ledger in ("destroyed",) and observed in ("destroyed", "missing"):
        return True
    if ledger == "purged" and observed in ("purged", "missing", "destroyed"):
        return True
    if ledger in ("quarantined", "sealed") and observed in ("quarantined", "sealed"):
        return True
    if ledger in ("present", "resurrected", "offline_pending") and observed in ("present",):
        return True
    return ledger == observed


# ---------------------------------------------------------------------------
# Release documents + device destruction certificate -> final destruction
# ---------------------------------------------------------------------------

def register_release(db, s: Dict[str, Any]) -> Dict[str, Any]:
    ensure_schema(db)
    rid = s["id"]
    notice_id = s["notice_id"]
    n = one(db, "SELECT * FROM hold_notices_rich WHERE id=?", (notice_id,))
    if not n:
        return {"decision": "unknown_notice"}
    issuer = one(db, "SELECT * FROM hold_issuers WHERE id=?", (s.get("issuer", n["issuer"]),))
    problems = []
    if not issuer or not issuer["trusted"]:
        problems.append("unverified_issuer")
    if s.get("case_ref") != n["case_ref"]:
        problems.append("case_scope_mismatch")
    if s.get("issuer") and s["issuer"] != n["issuer"] and not s.get("issuer_override_trusted"):
        problems.append("issuer_mismatch")
    if int(s["released_at"]) < n["arrived_at"]:
        problems.append("release_before_notice_arrival")
    verified = 1 if not problems else 0
    validation = "verified" if verified else "invalid:" + ",".join(problems)
    db.execute("INSERT OR REPLACE INTO hold_releases VALUES(?,?,?,?,?,?,?,?)",
               (rid, notice_id, s.get("issuer", n["issuer"]), s.get("case_ref", n["case_ref"]),
                int(s["released_at"]), s.get("document_ref", rid), verified, validation))
    if verified:
        db.execute("UPDATE hold_notices_rich SET status='released' WHERE id=?", (notice_id,))
    return {"decision": "release_verified" if verified else "release_rejected",
            "id": rid, "validation": validation, "problems": problems}


def register_device_cert(db, s: Dict[str, Any]) -> Dict[str, Any]:
    ensure_schema(db)
    cid = s["id"]
    db.execute("INSERT OR REPLACE INTO device_destruction_certs "
               "(id,copy_id,fragment_id,media_ref,method,issued_by,at,digest,verification) "
               "VALUES(?,?,?,?,?,?,?,?,?)",
               (cid, s.get("copy_id"), s.get("fragment_id"), s.get("media_ref"),
                s.get("method", "cryptographic_erase_and_shred"), s.get("issued_by", "certified-media-destructor"),
                int(s.get("at", 0)), s.get("digest"), s.get("verification", "device_level_verified")))
    return {"decision": "device_certificate_recorded", "id": cid}


def release_and_destroy(db, s: Dict[str, Any]) -> Dict[str, Any]:
    """Verify release (+ device cert for quarantine), destroy held bytes."""
    ensure_schema(db)
    at = int(s.get("at", 40))
    ticket_id = s["ticket_id"]

    release = s.get("release")
    if release:
        rel = register_release(db, {**release, "id": release.get("id", f"rel-{ticket_id}")})
        if rel["decision"] != "release_verified":
            return rel
    rel_row = one(db, "SELECT * FROM hold_releases WHERE notice_id=? AND verified=1 ORDER BY released_at DESC LIMIT 1",
                  (s["notice_id"],)) if s.get("notice_id") else None
    if not rel_row:
        return {"decision": "valid_release_document_required", "ticket_id": ticket_id}

    frag_id = s.get("fragment_id")
    frag = one(db, "SELECT * FROM hold_fragments WHERE id=?", (frag_id,)) if frag_id else None
    if not frag:
        # find by ticket's scope hold
        scope = resolve_scope(db, ticket_id, at)
        if scope.get("hold_hits"):
            nid = scope["hold_hits"][0]["notice_id"]
            frag = one(db, "SELECT * FROM hold_fragments WHERE notice_id=? ORDER BY sealed_at DESC LIMIT 1", (nid,))
    if not frag:
        return {"decision": "no_held_fragment"}

    # Quarantine of a whole physical block additionally needs a device-level
    # destruction certificate; a logical delete is not enough.
    device_cert_id = s.get("device_cert_id")
    cert = one(db, "SELECT * FROM device_destruction_certs WHERE id=?", (device_cert_id,)) if device_cert_id else None
    if not frag["minimized"]:
        if not cert and not s.get("device_cert_id"):
            return {"decision": "device_destruction_certificate_required",
                    "fragment_id": frag["id"], "release_verified": True}
        if not cert:
            register_device_cert(db, {"id": device_cert_id, "copy_id": frag["copy_id"],
                                      "fragment_id": frag["id"], "at": at,
                                      "media_ref": s.get("media_ref", "device"),
                                      "digest": frag["digest"]})
            cert = one(db, "SELECT * FROM device_destruction_certs WHERE id=?", (device_cert_id,))

    # Destroy the held copy / fragment object.
    copy_id = frag["copy_id"]
    cp = one(db, "SELECT * FROM byte_copies WHERE id=?", (copy_id,))
    if cp:
        if cp["kind"] == "object" or cp["location"] in ("hold-vault",) or True:
            _external_mutate_destroy(db, cp, at)
        _set_copy_state(db, copy_id, "destroyed", at,
                        {"kind": "post_release_destruction", "release_id": rel_row["id"],
                         "device_cert_id": cert["id"] if cert else None})
        db.execute("UPDATE external_commands SET state='acked' WHERE copy_id=? AND state='unacked'", (copy_id,))
    db.execute("UPDATE hold_fragments SET state='released_destroyed', released_at=?, destroyed_at=?, "
               "release_id=?, device_cert_id=? WHERE id=?",
               (rel_row["released_at"], at, rel_row["id"], cert["id"] if cert else None, frag["id"]))

    verification = verify_copies(db, ticket_id, at + 1)
    proof = issue_completion_proof(db, {
        "id": s.get("proof_id", f"proof-complete-{ticket_id}"),
        "ticket_id": ticket_id, "at": at + 2,
        "release_id": rel_row["id"], "device_cert_id": cert["id"] if cert else None,
        "fragment_id": frag["id"], "verification": verification,
        "amends_id": s.get("amends_id")})
    return {"decision": "held_bytes_destroyed_after_release", "ticket_id": ticket_id,
            "fragment_id": frag["id"], "proof_id": proof["doc_id"],
            "device_cert_id": cert["id"] if cert else None, "conclusion": "deleted_complete"}


# ---------------------------------------------------------------------------
# Append-only compliance documents (proofs & preservation schedules)
# ---------------------------------------------------------------------------

def issue_segmented_proof(db, p: Dict[str, Any]) -> Dict[str, Any]:
    ensure_schema(db)
    doc_id = p["id"]
    if one(db, "SELECT id FROM compliance_docs WHERE id=?", (doc_id,)):
        return {"doc_id": doc_id, "decision": "proof_exists"}
    scope = p["scope"]
    ticket_id = p["ticket_id"]
    destroyed, retained, unverified = _segment_lists(db, scope, p)
    body = {
        "doc_id": doc_id, "kind": "deletion_proof", "ticket_id": ticket_id,
        "customer": scope["customer"], "host": scope["host"], "claim_epoch": scope.get("claim_epoch"),
        "scope": {"before_at": scope["before_at"], "digests": scope["digests"],
                  "blocks": scope["blocks"], "excluded_later_epochs": scope["excluded"]},
        "disposition": p.get("disposition"),
        "destroyed_segments": destroyed,
        "retained_segments": retained,
        "unverified_segments": unverified,
        "other_tenant_handling": _other_tenant_handling(db, scope, p),
        "conclusion": p["conclusion"],
        "physical_deletion_complete": p.get("physical_deletion_complete",
                                            p["conclusion"] == "deleted_complete"),
        "verification": p.get("verification"),
        "issued_at": p["at"],
    }
    dgst = digest_bytes(canonical(body))
    db.execute("INSERT INTO compliance_docs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
               (doc_id, doc_id, "deletion_proof", scope["customer"], ticket_id, None, 1,
                p["at"], p["conclusion"], _j(body), dgst, "delivered"))
    return {"doc_id": doc_id, "body_digest": dgst, "decision": "proof_issued", "body": body}


def _segment_lists(db, scope: Dict[str, Any], p: Dict[str, Any]):
    destroyed, retained, unverified = [], [], []
    for cid in scope["copy_ids"]:
        cp = one(db, "SELECT * FROM byte_copies WHERE id=?", (cid,))
        if not cp:
            continue
        seg = {"copy_id": cid, "kind": cp["kind"], "location": cp["location"],
               "object_key": cp["object_key"], "version": cp["version"],
               "digest": cp["digest"], "byte_count": cp["byte_count"], "state": cp["state"],
               "responsible": cp["responsible"], "covers": cp["covers"]}
        if cp["state"] in ("destroyed", "purged", "missing"):
            seg["evidence"] = _evidence(cp)[-3:]
            destroyed.append(seg)
        elif cp["state"] in ("quarantined", "sealed"):
            frag = one(db, "SELECT * FROM hold_fragments WHERE copy_id=? ORDER BY sealed_at DESC LIMIT 1", (cid,))
            seg["retention_reason"] = "legal_preservation"
            seg["minimized"] = bool(frag and frag["minimized"])
            seg["fragment_id"] = frag["id"] if frag else None
            seg["release_condition"] = ("verified release document" +
                                        (" and device-level destruction certificate" if frag and not frag["minimized"] else ""))
            retained.append(seg)
        elif cp["state"] == "offline_pending":
            seg["note"] = "channel unreachable; destruction not yet verified"
            unverified.append(seg)
        else:
            # present / resurrected leftovers are retained with an accountable owner
            seg["retention_reason"] = "unresolved_physical_copy"
            retained.append(seg)
    # New repacked copies are not in original scope copy_ids; append them.
    for key, created in (p.get("created") or {}).items():
        if key == "hold_fragment":
            cid = created["copy_id"] if "copy_id" in created else None
        else:
            cid = created.get("copy_id")
        if not cid:
            continue
        cp = one(db, "SELECT * FROM byte_copies WHERE id=?", (cid,))
        if not cp:
            continue
        seg = {"copy_id": cid, "kind": cp["kind"], "digest": cp["digest"],
               "byte_count": cp["byte_count"], "state": cp["state"],
               "responsible": cp["responsible"], "covers": cp["covers"]}
        if cp["state"] in ("destroyed",):
            destroyed.append(seg)
        elif cp["state"] == "sealed":
            seg["retention_reason"] = "legal_hold_minimal_fragment"
            retained.append(seg)
        elif cp["state"] == "present":
            seg["retention_reason"] = "other_tenant_retained_object"
            retained.append(seg)
    return destroyed, retained, unverified


def _other_tenant_handling(db, scope: Dict[str, Any], p: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for o in scope.get("other_tenant_records", []):
        cust = o["customer"]
        copy = one(db, "SELECT * FROM byte_copies WHERE block_id=? AND covers='repacked_tenant_object' "
                       "AND record_ids LIKE ?", (scope["blocks"][0], f'%"{o["record_id"]}"%'))
        if copy:
            out.append({"customer": cust, "disposition": "independent_retained_object",
                        "copy_id": copy["id"], "digest": copy["digest"], "disclosed_in_erasure_proof": False})
        else:
            q = one(db, "SELECT id FROM byte_copies WHERE block_id=? AND state='quarantined' LIMIT 1",
                    (scope["blocks"][0],))
            out.append({"customer": cust, "disposition": "contained_in_quarantined_shared_block",
                        "copy_id": q["id"] if q else None,
                        "ordinary_access": "revoked", "separately_disclosed": False,
                        "note": "not destroyed and not publicly disclosed; access restricted to preservation custodian"})
    # de-dup by customer
    seen, uniq = set(), []
    for x in out:
        if x["customer"] in seen:
            continue
        seen.add(x["customer"])
        uniq.append(x)
    return uniq


def issue_preservation_schedule(db, p: Dict[str, Any]) -> Dict[str, Any]:
    ensure_schema(db)
    doc_id = p["id"]
    if one(db, "SELECT id FROM compliance_docs WHERE id=?", (doc_id,)):
        return {"doc_id": doc_id, "decision": "schedule_exists"}
    scope = p["scope"]
    frag = one(db, "SELECT * FROM hold_fragments WHERE id=?", (p["fragment_id"],)) if p.get("fragment_id") else None
    items = []
    if frag:
        n = one(db, "SELECT * FROM hold_notices_rich WHERE id=?", (frag["notice_id"],))
        items.append({
            "fragment_id": frag["id"], "notice_id": frag["notice_id"],
            "case_ref": n["case_ref"] if n else None,
            "issuer": n["issuer"] if n else None,
            "arrived_at": n["arrived_at"] if n else None,
            "record_ids": _loads(frag["record_ids"], []),
            "minimized": bool(frag["minimized"]),
            "whole_block_over_retention": not bool(frag["minimized"]),
            "digest": frag["digest"], "byte_count": frag["byte_count"], "vault": frag["vault"],
            "state": frag["state"], "responsible": SCENE_DEFAULTS["custodian"],
            "release_condition": "verified release document" +
                                 (" + device-level destruction certificate" if not frag["minimized"] else ""),
        })
    body = {"doc_id": doc_id, "kind": "preservation_schedule", "ticket_id": p["ticket_id"],
            "customer": scope["customer"], "issued_at": p["at"], "items": items,
            "whole_block": bool(p.get("whole_block"))}
    dgst = digest_bytes(canonical(body))
    db.execute("INSERT INTO compliance_docs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
               (doc_id, doc_id, "preservation_schedule", scope["customer"], p["ticket_id"], None, 1,
                p["at"], "preservation_active", _j(body), dgst, "delivered"))
    return {"doc_id": doc_id, "body_digest": dgst, "decision": "preservation_schedule_issued", "body": body}


def issue_completion_proof(db, p: Dict[str, Any]) -> Dict[str, Any]:
    doc_id = p["id"]
    if one(db, "SELECT id FROM compliance_docs WHERE id=?", (doc_id,)):
        return {"doc_id": doc_id, "decision": "proof_exists"}
    ticket = one(db, "SELECT * FROM erasure_tickets WHERE id=?", (p["ticket_id"],))
    customer = ticket["customer"] if ticket else None
    body = {"doc_id": doc_id, "kind": "completion_proof", "ticket_id": p["ticket_id"],
            "customer": customer, "issued_at": p["at"], "conclusion": "deleted_complete",
            "physical_deletion_complete": True, "release_id": p.get("release_id"),
            "device_cert_id": p.get("device_cert_id"), "fragment_id": p.get("fragment_id"),
            "verification": p.get("verification")}
    dgst = digest_bytes(canonical(body))
    root_id = p.get("amends_id") or doc_id
    db.execute("INSERT INTO compliance_docs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
               (doc_id, root_id, "completion_proof", customer, p["ticket_id"], p.get("amends_id"),
                _next_revision(db, root_id), p["at"], "deleted_complete", _j(body), dgst, "delivered"))
    return {"doc_id": doc_id, "body_digest": dgst, "decision": "completion_proof_issued", "body": body}


def append_correction(db, s: Dict[str, Any]) -> Dict[str, Any]:
    """Append a correction/amendment; the original document is never mutated."""
    ensure_schema(db)
    original = one(db, "SELECT * FROM compliance_docs WHERE id=?", (s["amends_id"],))
    if not original:
        return {"decision": "unknown_document"}
    corr_id = s["id"]
    if one(db, "SELECT id FROM compliance_docs WHERE id=?", (corr_id,)):
        return {"decision": "correction_exists", "doc_id": corr_id}
    original_body = _loads(original["body"], {})
    correction_body = {
        "doc_id": corr_id, "kind": "correction", "amends_id": original["id"],
        "root_id": original["root_id"], "issued_at": int(s["at"]),
        "reason": s.get("reason"), "corrects_conclusion": original["conclusion"],
        "corrected_conclusion": s.get("conclusion"),
        "corrected_facts": s.get("corrected", {}),
        "original_document_digest": original["body_digest"],
        "original_retained_unchanged": True,
    }
    if s.get("append_body"):
        correction_body.update(s["append_body"])
    dgst = digest_bytes(canonical(correction_body))
    rev = _next_revision(db, original["root_id"])
    db.execute("INSERT INTO compliance_docs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
               (corr_id, original["root_id"], "correction", original["customer"], original["ticket_id"],
                original["id"], rev, int(s["at"]), s.get("conclusion", "corrected"),
                _j(correction_body), dgst, "delivered"))
    return {"decision": "correction_appended", "doc_id": corr_id, "amends_id": original["id"],
            "revision": rev, "original_digest_unchanged": original["body_digest"]}


def _next_revision(db, root_id: str) -> int:
    row = one(db, "SELECT MAX(revision) AS m FROM compliance_docs WHERE root_id=?", (root_id,))
    return int((row or {}).get("m") or 0) + 1


def documents(db, ticket_id: Optional[str] = None) -> List[Dict[str, Any]]:
    if ticket_id:
        ds = rows(db, "SELECT * FROM compliance_docs WHERE ticket_id=? ORDER BY issued_at, rowid", (ticket_id,))
    else:
        ds = rows(db, "SELECT * FROM compliance_docs ORDER BY issued_at, rowid")
    out = []
    for d in ds:
        item = {k: d[k] for k in d.keys()}
        item["body"] = _loads(d["body"], {})
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# Customer-facing statement
# ---------------------------------------------------------------------------

def customer_statement(db, s: Dict[str, Any]) -> Dict[str, Any]:
    ensure_schema(db)
    ticket_id = s["ticket_id"]
    at = int(s.get("at", 45))
    ticket = one(db, "SELECT * FROM erasure_tickets WHERE id=?", (ticket_id,))
    if not ticket:
        return {"decision": "unknown_ticket"}
    scope_row = one(db, "SELECT scope FROM scope_resolutions WHERE ticket_id=?", (ticket_id,))
    scope = _loads(scope_row["scope"], None) if scope_row else resolve_scope(db, ticket_id, at)
    if scope and scope.get("decision") == "unknown_ticket":
        scope = None

    destroyed, retained, unverified, remaining = [], [], [], []
    other_tenant_objects = []
    copies = rows(db, "SELECT * FROM byte_copies WHERE block_id IN "
                      "(SELECT id FROM access_blocks WHERE host=?)", (ticket["host"],))
    if scope and scope.get("blocks"):
        block_set = set(scope["blocks"])
        copies = [c for c in copies if c["block_id"] in block_set]
    for cp in copies:
        entry = {"copy_id": cp["id"], "kind": cp["kind"], "location": cp["location"],
                 "version": cp["version"], "digest": cp["digest"], "byte_count": cp["byte_count"],
                 "state": cp["state"], "responsible": cp["responsible"]}
        other_tenant = cp["kind"] == "repacked_tenant_object"
        entry["interest"] = "other_tenant" if other_tenant else "requester"
        if cp["state"] in ("destroyed", "purged"):
            destroyed.append(entry)
            continue
        if cp["state"] == "offline_pending":
            unverified.append(entry)
            remaining.append({**entry, "why": "destruction_unverified"})
            continue
        if cp["state"] in ("quarantined", "sealed", "present", "resurrected", "missing"):
            frag = one(db, "SELECT * FROM hold_fragments WHERE copy_id=? ORDER BY rowid DESC LIMIT 1", (cp["id"],))
            if frag:
                entry["minimized"] = bool(frag["minimized"])
                entry["release_condition"] = ("verified release" +
                                              (" + device destruction certificate" if not frag["minimized"] else ""))
            if other_tenant and cp["state"] == "present":
                entry["retention_reason"] = "other_tenants_independent_object"
                other_tenant_objects.append(entry)
                remaining.append({**entry, "why": "other_tenant_retention"})
                continue
            if cp["state"] == "missing":
                # Ledger had a migration copy that is now absent without a
                # destruction attestation: treat as unverified, not retained.
                unverified.append({**entry, "note": "absent without destruction attestation"})
                continue
            retained.append(entry)
            remaining.append({**entry, "why": ("legal_preservation" if frag else "unresolved_physical_copy")})

    requester_retained = [e for e in retained if e["interest"] == "requester"]
    requester_unverified = [e for e in unverified if e.get("interest", "requester") == "requester"]

    # A quarantined whole block also contains the other tenant's records.  They
    # are neither disclosed nor destroyed; surface that containment explicitly.
    if scope and scope.get("blocks"):
        qblock = next((e for e in requester_retained
                       if e["state"] == "quarantined" and e.get("minimized") is False), None)
        if qblock:
            qcopy = one(db, "SELECT block_id FROM byte_copies WHERE id=?", (qblock["copy_id"],))
            bid = qcopy["block_id"] if qcopy else scope["blocks"][0]
            tenants = rows(db, "SELECT DISTINCT customer FROM access_records WHERE block_id=? AND customer<>?",
                           (bid, ticket["customer"]))
            for t in tenants:
                other_tenant_objects.append({
                    "customer": t["customer"],
                    "disposition": "contained_in_quarantined_shared_block",
                    "copy_id": qblock["copy_id"], "ordinary_access": "revoked",
                    "disclosed_publicly": False, "destroyed_by_requester_workflow": False,
                    "responsible": SCENE_DEFAULTS["custodian"]})
                remaining.append({"copy_id": qblock["copy_id"], "interest": "other_tenant",
                                  "responsible": SCENE_DEFAULTS["custodian"],
                                  "why": "other_tenant_bytes_contained_in_quarantine"})

    docs_ = documents(db, ticket_id)
    latest_conclusion = None
    if docs_:
        for d in reversed(docs_):
            if d["kind"] in ("deletion_proof", "completion_proof"):
                latest_conclusion = d["conclusion"]
                break

    if any(e["state"] == "quarantined" for e in requester_retained):
        conclusion = "incomplete_quarantined_whole_block"
        complete = False
    elif requester_retained:
        conclusion = latest_conclusion or "partially_deleted_legal_hold_retained"
        complete = False
    elif requester_unverified:
        conclusion = "deletion_unverified_pending_reports"
        complete = False
    else:
        conclusion = "deleted_complete"
        complete = True

    return {"decision": "statement", "ticket_id": ticket_id, "customer": ticket["customer"],
            "conclusion": conclusion, "physical_deletion_complete": complete,
            "scope": {k: scope[k] for k in ("host", "before_at", "digests", "blocks", "excluded")} if scope else None,
            "destroyed_bytes": destroyed, "retained_bytes": retained,
            "unverified_bytes": unverified, "other_tenant_objects": other_tenant_objects,
            "remaining_responsibility": remaining,
            "documents": [{"id": d["id"], "kind": d["kind"], "revision": d["revision"],
                           "amends_id": d["amends_id"], "conclusion": d["conclusion"],
                           "issued_at": d["issued_at"], "body_digest": d["body_digest"]} for d in docs_]}


# ---------------------------------------------------------------------------
# Event-sourced op adapter
# ---------------------------------------------------------------------------

def run(db, step: Dict[str, Any]) -> Dict[str, Any]:
    ensure_schema(db)
    _DB.db = db
    op = step["op"]

    if op in ("scene", "build_scene", "seed_scene"):
        return build_scene(db, step)
    if op in ("record", "register_record", "log_record"):
        db.execute("INSERT OR REPLACE INTO access_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                   (step["id"], step["block_id"], step.get("seq"), step["customer"], step.get("host"),
                    step.get("claim_epoch"), int(step["at"]), step.get("request_ref"), step.get("scope_tag"),
                    step.get("digest"), int(step.get("byte_count", 0)), step.get("payload")))
        return {"decision": "recorded"}
    if op in ("issuer", "trust_issuer", "register_issuer"):
        db.execute("INSERT OR REPLACE INTO hold_issuers VALUES(?,?,?,?)",
                   (step["id"], step.get("name", step["id"]), step.get("kind", "court"),
                    1 if step.get("trusted", True) else 0))
        return {"decision": "issuer_registered"}
    if op in ("receive_hold", "hold_notice_rich", "register_hold_notice"):
        refs = step.get("request_refs")
        db.execute("INSERT OR REPLACE INTO hold_notices_rich "
                   "(id,customer,host,claim_epoch,start_at,end_at,request_refs,scope_tag,case_ref,"
                   "cause,issuer,issued_at,arrived_at,valid_until,claimed_early,status,validation) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (step["id"], step["customer"], step.get("host"), step.get("claim_epoch"),
                    step.get("start_at"), step.get("end_at"), _j(refs) if refs is not None else None,
                    step.get("scope_tag"), step.get("case_ref"), step.get("cause"),
                    step["issuer"], int(step["issued_at"]), int(step["arrived_at"]),
                    step.get("valid_until"),
                    1 if int(step["arrived_at"]) > int(step["issued_at"]) else 0,
                    "received", "pending_validation"))
        result = verify_notice(db, step["id"])
        return result
    if op in ("verify_notice", "validate_hold"):
        return verify_notice(db, step["notice_id"])
    if op in ("release", "release_hold", "register_release"):
        return register_release(db, step)
    if op in ("device_cert", "register_device_cert", "device_destruction_certificate"):
        return register_device_cert(db, step)
    if op in ("scope", "resolve_scope", "deletion_scope", "resolve"):
        return resolve_scope(db, step["ticket_id"], step.get("at"),
                             step.get("claim_epoch"), step.get("byte_digest"))
    if op in ("reconcile", "reconcile_copies", "recognize", "recognize_deletions", "adopt", "verify_external"):
        return reconcile(db, step)
    if op in ("recover_copy", "safe_recover", "recover"):
        return recover_copy(db, step["copy_id"], int(step.get("at", 30)), step.get("hold_context"))
    if op in ("destroy_external", "issue_destroy", "send_destroy"):
        return issue_destroy(db, step["copy_id"], int(step.get("at", 30)),
                             step.get("outcome", "acked"), step.get("action", "destroy"))
    if op in ("gateway_report", "cache_report", "offline_report", "backfill_report"):
        return gateway_report(db, step)
    if op in ("split", "disposition_split", "recompact", "split_disposition", "minimize_and_destroy"):
        return disposition_split(db, step)
    if op in ("quarantine", "quarantine_block", "disposition_quarantine"):
        if step.get("copy_id") and not step.get("ticket_id"):
            return quarantine_copy(db, step["copy_id"], int(step.get("at", 30)))
        return disposition_quarantine(db, step)
    if op in ("ordinary_access", "access_attempt", "read_attempt"):
        return ordinary_access(db, step)
    if op in ("release_and_destroy", "destroy_after_release", "complete_after_release"):
        return release_and_destroy(db, step)
    if op in ("correct", "correct_proof", "amend_proof", "append_correction", "correction"):
        return append_correction(db, step)
    if op in ("issue_proof", "segmented_proof"):
        scope = resolve_scope(db, step["ticket_id"], int(step.get("at", 30)))
        return issue_segmented_proof(db, {**step, "scope": scope})
    if op in ("statement", "customer_statement", "report", "final_statement"):
        return customer_statement(db, step)
    if op in ("documents", "list_documents"):
        return {"decision": "documents", "documents": documents(db, step.get("ticket_id"))}
    if op in ("verify_copies", "verify", "audit"):
        return verify_copies(db, step["ticket_id"], int(step.get("at", 30)))
    raise ValueError(op)
