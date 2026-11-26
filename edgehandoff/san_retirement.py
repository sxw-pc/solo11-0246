"""Per-SAN retirement of a shared multi-name certificate.

The scene this module settles is deliberately split into four independent
state planes; none of them can be substituted for another:

1. Domain rights  -- each host's holder, delegation scope, claim generation
   (epoch) and revocation instant are adjudicated independently and can be
   sealed as an immutable verdict.
2. Certificate/key -- a multi-SAN certificate has one serial and one private
   key, so revocation is serial wide.  There is intentionally no per-SAN
   "revoke this bit" operation here: flipping a verdict cannot withdraw a key.
3. Gateway load   -- per gateway and gateway generation: the serial/key copy
   actually loaded and the observed SNI selection, with separate fact time
   (``observed_at``) and platform receipt time (``received_at``) so an
   offline gateway can back-fill late evidence without rewriting history.
4. Connections    -- individual client sessions per gateway/SNI/serial are
   evidence.  A gateway may physically accept a host on the shared cert while
   the independent domain verdict says that host's authorization ended.

Two completion routes are modelled under one revocation original:

* ``reissue_first``  -- issue/deploy a B-only certificate everywhere, prove B
  traffic moved, explicitly terminate the revoked host's sessions, then
  revoke the shared serial and collect removal evidence.
* ``quarantine_drain`` -- isolate the offline gateway from new entries, let
  established sessions drain (no forced cut of the surviving holder), accept
  the late report, revoke once drained, then give B its new certificate and
  restore new entries (B pays a no-new-connection window).

All operations are deterministic and clocked by caller supplied integers so
``store.replay`` converges.
"""

import json
import sqlite3

from .store import one, rows
from . import certificate as certificate_subsystem

# ---------------------------------------------------------------------------
# Decision token compatibility wrapper
# ---------------------------------------------------------------------------


class Decision(str):
    """A canonical decision token that also compares equal to its synonyms.

    The scenario vocabulary has several reasonable names for the same verdict
    (``isolated`` vs ``quarantined``).  The stored/JSON value and the canonical
    attribute are always the canonical snake_case token; only equality accepts
    the curated synonym set for this one verdict.
    """

    __slots__ = ("aliases", "canonical")

    def __new__(cls, canonical, aliases=()):
        obj = super().__new__(cls, canonical)
        obj.canonical = canonical
        obj.aliases = frozenset(aliases) | {canonical}
        return obj

    def __eq__(self, other):
        if isinstance(other, str):
            return str.__eq__(str(self), other) or other in self.aliases
        return NotImplemented

    def __ne__(self, other):  # pragma: no cover - trivial
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __hash__(self):
        return str.__hash__(self)


def decision(canonical, *aliases):
    return Decision(canonical, aliases)


def out(canonical, aliases=(), **payload):
    result = {"decision": Decision(canonical, aliases)}
    result.update(payload)
    return result


# ---------------------------------------------------------------------------
# Schema (created lazily so importing the module never mutates a database and
# replay into an empty database recreates exactly the same rows)
# ---------------------------------------------------------------------------

SAN_SCHEMA = """
CREATE TABLE IF NOT EXISTS sr_cases(
  id TEXT PRIMARY KEY,
  serial TEXT, owner TEXT, hosts_json TEXT, revoked_hosts_json TEXT,
  gateways_json TEXT, started_at INTEGER, route TEXT, state TEXT,
  b_serial TEXT, completed_at INTEGER, drain_confirmed_at INTEGER,
  b_verified_at INTEGER, config_json TEXT
);
CREATE TABLE IF NOT EXISTS sr_verdicts(
  case_id TEXT, host TEXT, at INTEGER, owner TEXT,
  holder TEXT, claim_epoch INTEGER, lease_until INTEGER, claim_status TEXT,
  delegation_id TEXT, scope TEXT, grantee TEXT, granted_at INTEGER,
  delegation_until INTEGER, revoked INTEGER, revoked_at INTEGER,
  authorized INTEGER, state TEXT, reason TEXT,
  PRIMARY KEY(case_id,host,at,owner)
);
CREATE TABLE IF NOT EXISTS sr_reports(
  id TEXT PRIMARY KEY, gateway TEXT, gateway_epoch INTEGER, kind TEXT,
  serial TEXT, fingerprint TEXT, loaded INTEGER, sni_json TEXT,
  observed_at INTEGER, received_at INTEGER, online INTEGER,
  stale INTEGER, late INTEGER, payload_json TEXT
);
CREATE TABLE IF NOT EXISTS sr_copies(
  gateway TEXT, gateway_epoch INTEGER, serial TEXT,
  fingerprint TEXT, loaded INTEGER, sni_json TEXT,
  observed_at INTEGER, received_at INTEGER, report_id TEXT, removed_at INTEGER,
  PRIMARY KEY(gateway,gateway_epoch,serial)
);
CREATE TABLE IF NOT EXISTS sr_posture(
  gateway TEXT PRIMARY KEY, reachable INTEGER, quarantined INTEGER,
  quarantine_at INTEGER, accepting_new INTEGER,
  updated_at INTEGER, recovered_at INTEGER
);
CREATE TABLE IF NOT EXISTS sr_connections(
  id TEXT PRIMARY KEY, gateway TEXT, gateway_epoch INTEGER,
  sni TEXT, serial TEXT, fingerprint TEXT, client TEXT,
  opened_at INTEGER, observed_at INTEGER, closed_at INTEGER, end_reason TEXT,
  physical INTEGER, policy TEXT, authorized INTEGER,
  open_authorized INTEGER, open_right_state TEXT,
  right_state TEXT, cert_state TEXT, classification TEXT,
  detail_json TEXT
);
CREATE TABLE IF NOT EXISTS sr_certs(
  serial TEXT PRIMARY KEY, fingerprint TEXT, revoked_at INTEGER,
  b_only INTEGER, case_id TEXT
);
CREATE TABLE IF NOT EXISTS sr_actions(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT, kind TEXT, at INTEGER, detail_json TEXT
);
"""

def ensure_schema(db):
    """Create the SAN retirement tables idempotently.

    DDL is issued statement by statement (never ``executescript``, which emits
    an implicit COMMIT and would break the store's open transaction).
    """

    try:
        row = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sr_cases'"
        ).fetchone()
    except sqlite3.Error:
        row = None
    if row:
        return
    for statement in SAN_SCHEMA.split(";"):
        statement = statement.strip()
        if statement:
            db.execute(statement)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _json(value, default=None):
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _dump(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).lower() in ("1", "true", "yes", "on")


def _cid(x, include_id=False):
    """Case identifier across the plausible field names."""
    value = (x.get("case") or x.get("case_id") or x.get("handoff")
             or x.get("retirement") or x.get("retirement_id")
             or x.get("case_ref"))
    if value is None and include_id:
        value = x.get("id")
    return value


def _gw_ref(x, include_id=False):
    value = x.get("gateway") or x.get("gateway_id") or x.get("gw")
    if value is None and include_id:
        value = x.get("id")
    return value


def _clock(x, *names, default=0):
    for name in names or ("at", "ts", "time", "now"):
        if x.get(name) is not None:
            return x[name]
    return x.get("at", default) if not names else default


def _scope_covers(granted, requested="/"):
    if not granted:
        return False
    if granted == requested:
        return True
    if granted == "/":
        return True
    if requested == "/":
        # A narrower delegation cannot exercise the whole namespace.
        return False
    return requested.startswith(granted.rstrip("/") + "/")


def _sans(db, serial):
    cert = one(db, "SELECT * FROM certificates WHERE serial=?", (serial,))
    if not cert:
        return []
    return [r["host"] for r in db.execute(
        "SELECT host FROM order_names WHERE order_id=? ORDER BY host",
        (cert["order_id"],))]


def _cert_owner(db, serial):
    cert = one(db, "SELECT * FROM certificates WHERE serial=?", (serial,))
    if not cert:
        return None
    order = one(db, "SELECT owner FROM orders WHERE id=?", (cert["order_id"],))
    return order["owner"] if order else None


def _fingerprint(db, serial, supplied=None):
    if supplied:
        return supplied
    ext = one(db, "SELECT fingerprint FROM sr_certs WHERE serial=?", (serial,))
    if ext and ext["fingerprint"]:
        return ext["fingerprint"]
    return "key:" + str(serial)


def _gateways_for_serial(db, serial):
    ids = {r["gateway"] for r in db.execute(
        "SELECT DISTINCT gateway FROM deployments WHERE serial=?", (serial,))}
    ids.update(r["gateway"] for r in db.execute(
        "SELECT DISTINCT gateway FROM sr_copies WHERE serial=?", (serial,)))
    ids.update(r["gateway"] for r in db.execute(
        "SELECT DISTINCT gateway FROM sr_reports WHERE serial=?", (serial,)))
    return sorted(ids)


def _current_epoch(db, gateway):
    gw = one(db, "SELECT epoch FROM gateways WHERE id=?", (gateway,))
    return gw["epoch"] if gw else None


def _serial_load_state(db, gateway, epoch, serial):
    """Return ``(state, removed_at, source)`` for a serial on one generation.

    Positive per-generation report state wins.  A standard deployment receipt
    for the *current* gateway generation is evidence that the serial/key was
    loaded; an older-generation receipt cannot prove anything after a rebuild.
    """

    if epoch is None:
        return "unknown_gateway_generation", None, None
    copy = one(
        db,
        "SELECT loaded,removed_at FROM sr_copies WHERE gateway=? AND gateway_epoch=? AND serial=?",
        (gateway, epoch, serial))
    if copy is not None:
        return ("removed" if not copy["loaded"] else "loaded",
                copy["removed_at"], "report")
    deployment = one(
        db,
        "SELECT at FROM deployments WHERE serial=? AND gateway=? AND gateway_epoch=? "
        "ORDER BY at DESC LIMIT 1",
        (serial, gateway, epoch))
    if deployment is not None:
        return "loaded", None, "deployment_receipt"
    old = one(
        db,
        "SELECT gateway_epoch FROM deployments WHERE serial=? AND gateway=? "
        "ORDER BY gateway_epoch DESC LIMIT 1",
        (serial, gateway))
    if old is not None:
        return "stale_generation_state", None, "old_deployment_receipt"
    return "unknown_generation_state", None, None


# ---------------------------------------------------------------------------
# Event log reconstruction (the store records every original operation, so the
# instant a delegation was granted/revoked survives even though the delegation
# row itself only carries a revoked flag)
# ---------------------------------------------------------------------------


def _ownership_timing(db):
    granted_at = {}
    revoked_at = {}
    try:
        event_rows = rows(db, "SELECT subsystem,input FROM events ORDER BY seq")
    except sqlite3.OperationalError:  # pragma: no cover - events always exists
        return granted_at, revoked_at
    for event in event_rows:
        if event["subsystem"] != "ownership":
            continue
        step = _json(event["input"], {}) or {}
        op = step.get("op")
        if op == "delegate" and step.get("id"):
            granted_at.setdefault(step["id"], step.get("at"))
        elif op == "revoke_delegate" and step.get("id"):
            at = step.get("at")
            current = revoked_at.get(step["id"])
            if current is None:
                # None means "revoked at an unknown clock instant".  An
                # explicit integer always replaces the unknown marker.
                revoked_at[step["id"]] = at
            elif at is not None and (not isinstance(current, int) or at < current):
                revoked_at[step["id"]] = at
    return granted_at, revoked_at


def _cert_revoke_time(db, serial):
    ext = one(db, "SELECT revoked_at FROM sr_certs WHERE serial=?", (serial,))
    if ext and ext["revoked_at"] is not None:
        return ext["revoked_at"]
    cert = one(db, "SELECT status FROM certificates WHERE serial=?", (serial,))
    if not cert or cert["status"] != "revoked":
        return None
    revoke_at = None
    saw_revoke = False
    try:
        event_rows = rows(db, "SELECT subsystem,input FROM events ORDER BY seq")
    except sqlite3.OperationalError:  # pragma: no cover
        event_rows = []
    for event in event_rows:
        if event["subsystem"] != "certificate":
            continue
        step = _json(event["input"], {}) or {}
        if step.get("op") == "revoke" and step.get("serial") == serial:
            saw_revoke = True
            at = step.get("at")
            if at is not None:
                revoke_at = at if revoke_at is None else min(revoke_at, at)
    if revoke_at is not None:
        return revoke_at
    return "unknown" if saw_revoke else None


# ---------------------------------------------------------------------------
# Independent per-domain adjudication
# ---------------------------------------------------------------------------


def adjudicate_host(db, host, at, owner=None, serial=None, case=None):
    """Rule one host's platform authorization at clock instant ``at``.

    The returned mapping keeps holder, claim generation, delegation scope and
    the revocation instant side by side so every SAN is judged on its own
    original evidence.  This function is read-only and replay safe.
    """

    ensure_schema(db)
    if owner is None and serial is not None:
        owner = _cert_owner(db, serial)
    if owner is None and case is not None:
        case_row = one(db, "SELECT * FROM sr_cases WHERE id=?", (case,))
        if case_row:
            owner = case_row["owner"]
            if serial is None:
                serial = case_row["serial"]
                if owner is None:
                    owner = _cert_owner(db, serial)

    claim = one(db, "SELECT * FROM claims WHERE host=?", (host,))
    verdict = {
        "host": host,
        "at": at,
        "owner": owner,
        "holder": None,
        "claim_epoch": None,
        "lease_until": None,
        "claim_status": None,
        "delegation_id": None,
        "scope": None,
        "grantee": None,
        "granted_at": None,
        "delegation_until": None,
        "revoked": 0,
        "revoked_at": None,
        "authorized": False,
        "state": "unknown_host",
        "reason": "unknown_host",
    }
    if not claim:
        return verdict

    granted_clock, revoked_clock = _ownership_timing(db)
    verdict.update({
        "holder": claim["holder"],
        "claim_epoch": claim["epoch"],
        "lease_until": claim["lease_until"],
        "claim_status": claim["status"],
        "state": None,
        "reason": None,
    })

    # Lease/generation truth.  The simulation keeps a monotone claim row; the
    # simple and enforced rule is verified + unexpired at the adjudication.
    if claim["status"] == "released":
        verdict.update(state="claim_released", reason="claim_released")
        return verdict
    if claim["status"] != "verified":
        verdict.update(state="unverified", reason="unverified")
        return verdict
    if claim["lease_until"] is not None and claim["lease_until"] < at:
        verdict.update(state="lease_expired", reason="lease_expired")
        return verdict

    # The holder itself always speaks for the name while the lease is live.
    if owner is not None and claim["holder"] == owner:
        verdict.update(authorized=True, state="holder", reason="holder")
        return verdict

    delegations = rows(
        db,
        "SELECT * FROM delegations WHERE host=? ORDER BY id",
        (host,),
    )
    candidate = None
    blocker = None
    for delegation in delegations:
        if owner is not None and delegation["grantee"] != owner:
            continue
        if not _scope_covers(delegation["scope"], "/"):
            if blocker is None:
                blocker = ("scope_mismatch", delegation)
            continue

        did = delegation["id"]
        granted_at = granted_clock.get(did)
        revoked_at = revoked_clock.get(did)
        if revoked_at is None and delegation["revoked"]:
            # Row says revoked but no clocked event: keep an explicit unknown
            # marker rather than inventing a revocation instant.
            revoked_at = "unknown"
        if isinstance(revoked_at, int):
            delegation_revoked = revoked_at <= at
        else:
            delegation_revoked = bool(delegation["revoked"])

        base = {
            "delegation_id": did,
            "scope": delegation["scope"],
            "grantee": delegation["grantee"],
            "granted_at": granted_at,
            "delegation_until": delegation["until_ts"],
            "revoked": int(delegation["revoked"]),
            "revoked_at": None if revoked_at == "unknown" else revoked_at,
        }

        if isinstance(granted_at, int) and at < granted_at:
            blocker = blocker or ("delegation_future", delegation, base)
            continue
        if delegation["until_ts"] is not None and delegation["until_ts"] < at:
            blocker = blocker or ("delegation_expired", delegation, base)
            continue
        if delegation_revoked:
            blocker = blocker or ("delegation_revoked", delegation, base)
            continue

        # Effective delegation at this instant.
        if candidate is None or delegation["until_ts"] > candidate["delegation_until"]:
            candidate = base

    if candidate is not None:
        verdict.update(candidate)
        verdict.update(authorized=True, state="delegated", reason="delegated")
        return verdict

    if blocker is not None:
        state = blocker[0]
        base = blocker[2] if len(blocker) == 3 else {}
        verdict.update(base)
        verdict.update(authorized=False, state=state, reason=state)
        return verdict

    verdict.update(state="no_delegation", reason="no_delegation")
    return verdict


# Backwards friendly name.
rights_at = adjudicate_host


def seal_verdict(db, host, at, owner=None, case_id=None, serial=None):
    verdict = adjudicate_host(db, host, at, owner=owner, serial=serial, case=case_id)
    cid = case_id or ("adhoc:" + str(serial or host))
    db.execute(
        """INSERT INTO sr_verdicts(
             case_id,host,at,owner,holder,claim_epoch,lease_until,claim_status,
             delegation_id,scope,grantee,granted_at,delegation_until,revoked,
             revoked_at,authorized,state,reason)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(case_id,host,at,owner) DO UPDATE SET
             holder=excluded.holder, claim_epoch=excluded.claim_epoch,
             authorized=excluded.authorized, state=excluded.state,
             reason=excluded.reason, revoked_at=excluded.revoked_at""",
        (cid, host, at, owner, verdict["holder"], verdict["claim_epoch"],
         verdict["lease_until"], verdict["claim_status"],
         verdict["delegation_id"], verdict["scope"], verdict["grantee"],
         verdict["granted_at"], verdict["delegation_until"],
         verdict["revoked"], verdict["revoked_at"],
         int(verdict["authorized"]), verdict["state"], verdict["reason"]),
    )
    verdict["case_id"] = cid
    return verdict


# ---------------------------------------------------------------------------
# Case / revocation original
# ---------------------------------------------------------------------------


def _add_action(db, case_id, kind, at, **detail):
    db.execute(
        "INSERT INTO sr_actions(case_id,kind,at,detail_json) VALUES(?,?,?,?)",
        (case_id, kind, at, _dump(detail) if detail else None),
    )


def start_case(db, x):
    cid = _cid(x, include_id=True)
    serial = x.get("serial")
    at = x.get("at", 0)
    if not cid:
        return out("case_required", ["missing_case"])
    if not serial or not one(db, "SELECT serial FROM certificates WHERE serial=?", (serial,)):
        return out("unknown_certificate", ["serial_not_found"], serial=serial)
    if one(db, "SELECT id FROM sr_cases WHERE id=?", (cid,)):
        return out("case_conflict", ["retirement_conflict", "conflict"], case=cid)

    owner = x.get("owner") or _cert_owner(db, serial)
    sans = _sans(db, serial)
    requested_hosts = x.get("hosts") or x.get("names") or sans
    revoked_hosts = x.get("revoked_hosts")
    if revoked_hosts is None:
        single = x.get("revoked_host") or x.get("revoked_san")
        revoked_hosts = [single] if single else []
    revoked_hosts = list(revoked_hosts)

    rulings = {}
    for host in requested_hosts:
        verdict = seal_verdict(db, host, at, owner=owner, case_id=cid, serial=serial)
        rulings[host] = {
            "authorized": verdict["authorized"],
            "state": verdict["state"],
            "revoked_at": verdict["revoked_at"],
            "claim_epoch": verdict["claim_epoch"],
            "holder": verdict["holder"],
        }
        if not revoked_hosts and not verdict["authorized"]:
            revoked_hosts.append(host)

    gateways = x.get("gateways") or _gateways_for_serial(db, serial)
    db.execute(
        """INSERT INTO sr_cases(id,serial,owner,hosts_json,revoked_hosts_json,
             gateways_json,started_at,route,state,b_serial,completed_at,
             drain_confirmed_at,b_verified_at,config_json)
           VALUES(?,?,?,?,?,?,?,NULL,'open',NULL,NULL,NULL,NULL,?)""",
        (cid, serial, owner, _dump(list(requested_hosts)), _dump(revoked_hosts),
         _dump(list(gateways)), at,
         _dump({"started_by": x.get("request_id")})),
    )
    _add_action(db, cid, "start", at, serial=serial,
                revoked_hosts=revoked_hosts, gateways=gateways)
    return out("retirement_started", ["started", "case_opened", "opened",
                                      "case_started", "handoff_started"],
               case=cid, serial=serial, hosts=list(requested_hosts),
               revoked_hosts=revoked_hosts, gateways=list(gateways),
               rulings=rulings)


ROUTE_ALIASES = {
    "reissue_first": "reissue_first",
    "reissue": "reissue_first",
    "migrate_b_first": "reissue_first",
    "b_first": "reissue_first",
    "route1": "reissue_first",
    "one": "reissue_first",
    "1": "reissue_first",
    "continuous_b": "reissue_first",
    "quarantine_drain": "quarantine_drain",
    "quarantine": "quarantine_drain",
    "drain_first": "quarantine_drain",
    "drain": "quarantine_drain",
    "route2": "quarantine_drain",
    "two": "quarantine_drain",
    "2": "quarantine_drain",
    "blackout_then_reissue": "quarantine_drain",
}


def choose_route(db, x):
    cid = _cid(x, include_id=True)
    raw = x.get("route") or x.get("strategy") or x.get("method")
    case = one(db, "SELECT * FROM sr_cases WHERE id=?", (cid,)) if cid else None
    if not case:
        return out("unknown_case", ["case_not_found"], case=cid)
    route = ROUTE_ALIASES.get(str(raw))
    if route is None:
        return out("invalid_route", ["unknown_route"], route=raw)
    db.execute("UPDATE sr_cases SET route=?, state='routed' WHERE id=?", (route, cid))
    _add_action(db, cid, "route_selected", x.get("at", case["started_at"]), route=route)
    return out("route_selected", ["route_set", "planned"], case=cid, route=route)


# ---------------------------------------------------------------------------
# Gateway posture and load evidence
# ---------------------------------------------------------------------------


def _posture(db, gateway):
    row = one(db, "SELECT * FROM sr_posture WHERE gateway=?", (gateway,))
    if row:
        return row
    return {
        "gateway": gateway, "reachable": None, "quarantined": 0,
        "quarantine_at": None, "accepting_new": 1,
        "updated_at": None, "recovered_at": None,
    }


def _upsert_posture(db, gateway, at, **changes):
    current = _posture(db, gateway)
    fields = {
        "reachable": current["reachable"],
        "quarantined": current["quarantined"],
        "quarantine_at": current["quarantine_at"],
        "accepting_new": current["accepting_new"],
        "updated_at": at,
        "recovered_at": current["recovered_at"],
    }
    fields.update({k: v for k, v in changes.items() if v is not None or k in changes})
    db.execute(
        """INSERT INTO sr_posture(gateway,reachable,quarantined,quarantine_at,
             accepting_new,updated_at,recovered_at)
           VALUES(?,?,?,?,?,?,?)
           ON CONFLICT(gateway) DO UPDATE SET
             reachable=excluded.reachable, quarantined=excluded.quarantined,
             quarantine_at=excluded.quarantine_at,
             accepting_new=excluded.accepting_new,
             updated_at=excluded.updated_at,
             recovered_at=excluded.recovered_at""",
        (gateway, fields["reachable"], fields["quarantined"],
         fields["quarantine_at"], fields["accepting_new"],
         fields["updated_at"], fields["recovered_at"]),
    )


def quarantine_gateway(db, x):
    gateway = _gw_ref(x, include_id=True)
    at = x.get("at", 0)
    if _current_epoch(db, gateway) is None and not one(
            db, "SELECT 1 FROM sr_posture WHERE gateway=?", (gateway,)):
        return out("unknown_gateway", ["gateway_not_found"], gateway=gateway)
    _upsert_posture(db, gateway, at, quarantined=1, accepting_new=0,
                    quarantine_at=at)
    case_id = _cid(x)
    if case_id:
        _add_action(db, case_id, "quarantine", at, gateway=gateway)
    return out("quarantined", ["isolated", "gateway_isolated", "isolation_set"],
               gateway=gateway, accepting_new=False, at=at)


def lift_quarantine(db, x):
    gateway = _gw_ref(x, include_id=True)
    at = x.get("at", 0)
    posture = _posture(db, gateway)
    _upsert_posture(db, gateway, at, quarantined=0, accepting_new=1,
                    quarantine_at=posture["quarantine_at"])
    return out("quarantine_lifted", ["unisolated", "accepting_new"],
               gateway=gateway, accepting_new=True, at=at)


def recover_gateway(db, x):
    gateway = _gw_ref(x, include_id=True)
    at = x.get("at", x.get("recovered_at", 0))
    _upsert_posture(db, gateway, at, reachable=1, recovered_at=at)
    case_id = _cid(x)
    if case_id:
        _add_action(db, case_id, "recover", at, gateway=gateway)
    return out("recovered", ["online", "gateway_online", "reconnected",
                             "recovery_recorded"],
               gateway=gateway, reachable=True, at=at)


def mark_offline(db, x):
    gateway = _gw_ref(x, include_id=True)
    at = x.get("at", 0)
    _upsert_posture(db, gateway, at, reachable=0)
    return out("offline", ["gateway_offline", "marked_offline", "unreachable"],
               gateway=gateway, reachable=False, at=at)


def rebuild_gateway(db, x):
    """Bump a gateway generation through the existing gateway op.

    Key/load rows are generation keyed, so after a rebuild the new generation
    has no inherited load state and must supply fresh evidence.
    """

    gateway = _gw_ref(x, include_id=True)
    epoch = x.get("epoch") or x.get("gateway_epoch") or x.get("generation")
    result = certificate_subsystem.run(
        db, {"op": "gateway", "id": gateway, "epoch": epoch})
    if result.get("decision") == "gateway_ready":
        at = x.get("at", 0)
        case_id = _cid(x)
        if case_id and one(db, "SELECT 1 FROM sr_cases WHERE id=?", (case_id,)):
            _add_action(db, case_id, "gateway_rebuild", at,
                        gateway=gateway, epoch=epoch)
        result = out("gateway_rebuilt", ["gateway_ready", "rebuilt",
                                        "generation_rebuilt"],
                     gateway=gateway, epoch=epoch)
    return result


def _normalise_items(x):
    items = x.get("loads") or x.get("items") or x.get("certificates")
    if items is None:
        if x.get("serial") is not None:
            items = [{
                "serial": x.get("serial"),
                "loaded": x.get("loaded", x.get("installed", True)),
                "fingerprint": x.get("fingerprint") or x.get("key_fingerprint"),
                "sni": x.get("sni") or x.get("sni_map") or x.get("names"),
            }]
        else:
            items = []
    normalised = []
    for item in items:
        if isinstance(item, str):
            normalised.append({"serial": item, "loaded": True, "sni": None,
                               "fingerprint": None})
            continue
        sni = item.get("sni") or item.get("sni_map") or item.get("names")
        normalised.append({
            "serial": item.get("serial"),
            "loaded": _as_bool(item.get("loaded", item.get("installed", True)), True),
            "fingerprint": item.get("fingerprint") or item.get("key_fingerprint"),
            "sni": sni,
        })
    return normalised


def report_gateway(db, x):
    report_id = x.get("id") or x.get("report") or x.get("report_id")
    gateway = _gw_ref(x)
    observed_at = x.get("observed_at", x.get("at", 0))
    received_at = x.get("received_at", x.get("reported_at", observed_at))
    epoch = x.get("gateway_epoch", x.get("epoch"))
    if not report_id:
        return out("report_id_required", ["id_required"])
    if one(db, "SELECT id FROM sr_reports WHERE id=?", (report_id,)):
        return out("report_conflict", ["receipt_conflict", "conflict"], id=report_id)
    current_epoch = _current_epoch(db, gateway)
    if current_epoch is None:
        return out("unknown_gateway", ["gateway_not_found"], gateway=gateway)
    if epoch is None:
        epoch = current_epoch

    items = _normalise_items(x)
    online = x.get("online", x.get("reachable"))
    online_value = None if online is None else int(_as_bool(online))
    late = int(received_at is not None and observed_at is not None
               and received_at > observed_at)

    # Generation check: evidence from an old gateway generation is archived
    # (late receipts preserve history) but can never prove the current state.
    if epoch != current_epoch:
        stale = 1
        decision_token = ("stale_gateway", ["stale_report", "old_epoch",
                                           "gateway_epoch_mismatch"])
    else:
        stale = 0
        decision_token = ("reported", ["recorded", "evidence_recorded",
                                       "gateway_reported", "attested"])

    sni_map = x.get("sni_map") or x.get("sni_selection")
    db.execute(
        """INSERT INTO sr_reports(id,gateway,gateway_epoch,kind,serial,
             fingerprint,loaded,sni_json,observed_at,received_at,online,
             stale,late,payload_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (report_id, gateway, epoch, x.get("kind", "load"),
         x.get("serial"), x.get("fingerprint") or x.get("key_fingerprint"),
         None if x.get("loaded") is None else int(_as_bool(x.get("loaded"))),
         _dump(sni_map or x.get("sni")), observed_at, received_at,
         online_value, stale, late, _dump(x)),
    )

    if stale:
        return out(decision_token[0], decision_token[1], id=report_id,
                   gateway=gateway, report_epoch=epoch,
                   current_epoch=current_epoch, archived=True, stale=True)

    # Current generation: materialise per serial key-copy state.
    selection = {}
    if isinstance(sni_map, dict):
        selection.update(sni_map)
    for item in items:
        serial = item["serial"]
        if serial is None:
            continue
        fingerprint = _fingerprint(db, serial, item["fingerprint"])
        sni = item["sni"]
        sni_hosts = None
        if isinstance(sni, dict):
            for host, chosen in sni.items():
                selection[host] = chosen or serial
            sni_hosts = sorted(sni.keys())
        elif isinstance(sni, (list, tuple)):
            sni_hosts = list(sni)
            for host in sni_hosts:
                selection.setdefault(host, serial)
        elif isinstance(sni, str):
            sni_hosts = [sni]
            selection.setdefault(sni, serial)
        existing = one(
            db,
            "SELECT removed_at FROM sr_copies WHERE gateway=? AND gateway_epoch=? AND serial=?",
            (gateway, epoch, serial))
        removed_at = observed_at if not item["loaded"] else None
        if (not item["loaded"] and existing and existing["removed_at"] is not None
                and observed_at is not None):
            removed_at = existing["removed_at"]
        db.execute(
            """INSERT INTO sr_copies(gateway,gateway_epoch,serial,fingerprint,
                 loaded,sni_json,observed_at,received_at,report_id,removed_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(gateway,gateway_epoch,serial) DO UPDATE SET
                 fingerprint=excluded.fingerprint, loaded=excluded.loaded,
                 sni_json=excluded.sni_json, observed_at=excluded.observed_at,
                 received_at=excluded.received_at, report_id=excluded.report_id,
                 removed_at=excluded.removed_at""",
            (gateway, epoch, serial, fingerprint, int(item["loaded"]),
             _dump(sni_hosts), observed_at, received_at, report_id, removed_at),
        )

    # A report being processed is itself evidence the gateway reached the
    # platform at receipt time unless explicitly marked unreachable.
    if online_value is None or online_value == 1:
        posture = _posture(db, gateway)
        _upsert_posture(db, gateway, received_at,
                        reachable=1,
                        recovered_at=(received_at if posture["reachable"] == 0
                                      else posture["recovered_at"]))
    else:
        _upsert_posture(db, gateway, received_at, reachable=0)

    return out(decision_token[0], decision_token[1], id=report_id,
               gateway=gateway, epoch=epoch, items=len(items),
               late=bool(late), observed_at=observed_at,
               received_at=received_at)


# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------


def _connection_owner(db, conn_row):
    owner = _cert_owner(db, conn_row["serial"]) if conn_row["serial"] else None
    if owner:
        return owner
    return None


def connection_standing(db, conn, at=None):
    """Compute the independent standing of one connection record."""

    ensure_schema(db)
    if at is None:
        at = conn["closed_at"] if conn["closed_at"] is not None else conn["observed_at"]
    owner = _cert_owner(db, conn["serial"]) if conn["serial"] else None
    current = adjudicate_host(db, conn["sni"], at, owner=owner)
    opened = adjudicate_host(db, conn["sni"], conn["opened_at"], owner=owner)

    serial = conn["serial"]
    cert = one(db, "SELECT status,not_before,expires FROM certificates WHERE serial=?",
               (serial,)) if serial else None
    revoke_at = _cert_revoke_time(db, serial) if serial else None
    spans_revoke = bool(isinstance(revoke_at, int)
                        and conn["opened_at"] is not None
                        and conn["opened_at"] < revoke_at <= at
                        and (conn["closed_at"] is None or conn["closed_at"] >= revoke_at))

    if not opened["authorized"]:
        label = "unauthorized_at_open"
    elif not current["authorized"]:
        label = "domain_authorization_ended"
    elif cert and cert["status"] == "revoked":
        if isinstance(revoke_at, int) and conn["opened_at"] < revoke_at:
            label = "established_spanning_serial_revocation"
        else:
            label = "certificate_revoked"
    elif cert and at is not None and not (cert["not_before"] <= at < cert["expires"]):
        label = "certificate_outside_validity"
    else:
        label = "legitimate"

    return {
        "classification": label,
        "open_authorized": bool(opened["authorized"]),
        "open_right_state": opened["state"],
        "current_authorized": bool(current["authorized"]),
        "right_state": current["state"],
        "revoked_at": current["revoked_at"],
        "cert_status": cert["status"] if cert else "unknown",
        "serial_revoked_at": revoke_at,
        "spans_serial_revocation": spans_revoke,
        "active": conn["closed_at"] is None and bool(conn["physical"]),
    }


def _insert_connection(db, fields):
    db.execute(
        """INSERT INTO sr_connections(id,gateway,gateway_epoch,sni,serial,
             fingerprint,client,opened_at,observed_at,closed_at,end_reason,
             physical,policy,authorized,open_authorized,open_right_state,
             right_state,cert_state,classification,detail_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (fields["id"], fields["gateway"], fields.get("gateway_epoch"),
         fields["sni"], fields.get("serial"), fields.get("fingerprint"),
         fields.get("client"), fields["opened_at"], fields.get("observed_at"),
         fields.get("closed_at"), fields.get("end_reason"),
         int(fields.get("physical", 1)), fields.get("policy", "observed"),
         int(fields.get("authorized", 0)),
         int(fields.get("open_authorized", fields.get("authorized", 0))),
         fields.get("open_right_state"), fields.get("right_state"),
         fields.get("cert_state"), fields.get("classification"),
         _dump(fields.get("detail", {}))),
    )


def open_connection(db, x):
    cid = x.get("id") or x.get("connection")
    gateway = _gw_ref(x)
    sni = x.get("sni") or x.get("host") or x.get("servername") or x.get("hostname")
    serial = x.get("serial")
    at = x.get("at", 0)
    if not cid:
        return out("connection_id_required", ["id_required"])
    if one(db, "SELECT id FROM sr_connections WHERE id=?", (cid,)):
        return out("connection_conflict", ["conflict", "duplicate_connection"], id=cid)

    epoch = _current_epoch(db, gateway)
    if epoch is None:
        return out("unknown_gateway", ["gateway_not_found"], gateway=gateway)
    if x.get("gateway_epoch") is not None and x["gateway_epoch"] != epoch:
        return out("stale_gateway", ["gateway_epoch_mismatch", "deploy_denied"],
                   gateway=gateway, current_epoch=epoch)

    posture = _posture(db, gateway)
    if posture["quarantined"] or posture["accepting_new"] == 0:
        _insert_connection(db, {
            "id": cid, "gateway": gateway, "gateway_epoch": epoch, "sni": sni,
            "serial": serial, "opened_at": at, "observed_at": at, "closed_at": at,
            "end_reason": "rejected_new_entry", "physical": 0, "policy": "deny",
            "authorized": 0, "classification": "denied_new_entries_isolated",
            "right_state": "new_entries_isolated",
            "detail": {"reason": "new_entries_isolated"}})
        return out("new_entries_isolated", ["isolated", "quarantined",
                                            "new_connections_blocked"],
                   id=cid, gateway=gateway, admitted=False)

    owner = _cert_owner(db, serial)
    verdict = adjudicate_host(db, sni, at, owner=owner, serial=serial)

    def deny(token, aliases, classification, **extra):
        _insert_connection(db, {
            "id": cid, "gateway": gateway, "gateway_epoch": epoch, "sni": sni,
            "serial": serial, "opened_at": at, "observed_at": at, "closed_at": at,
            "end_reason": "rejected", "physical": 0, "policy": "deny",
            "authorized": int(verdict["authorized"]),
            "open_authorized": int(verdict["authorized"]),
            "open_right_state": verdict["state"], "right_state": verdict["state"],
            "classification": classification,
            "detail": {"reason": token, **extra}})
        return out(token, aliases, id=cid, admitted=False, sni=sni,
                   classification=classification,
                   right_state=verdict["state"], **extra)

    if not verdict["authorized"]:
        return deny("domain_authorization_revoked",
                    ["authorization_revoked", "delegation_revoked",
                     "san_authorization_revoked", "unauthorized",
                     "a_authorization_revoked", "right_revoked"],
                    "unauthorized_after_domain_revocation",
                    revoked_at=verdict["revoked_at"],
                    claim_epoch=verdict["claim_epoch"])

    cert = one(db, "SELECT * FROM certificates WHERE serial=?", (serial,))
    if not cert:
        return deny("certificate_unavailable", ["unknown_certificate"],
                    "denied_no_certificate")
    if cert["status"] != "active":
        revoke_at = _cert_revoke_time(db, serial)
        return deny("certificate_revoked", ["revoked", "serial_revoked"],
                    "denied_after_serial_revocation",
                    serial_revoked_at=revoke_at)
    if not (cert["not_before"] <= at < cert["expires"]):
        return deny("certificate_unavailable", ["certificate_outside_validity"],
                    "denied_certificate_time")
    if sni not in _sans(db, serial):
        return deny("wrong_san", ["san_mismatch", "certificate_san_mismatch"],
                    "denied_wrong_san")

    # Gateway load/SNI evidence cross-checks.  A positive current-generation
    # "not loaded" report means this gateway can no longer present the serial
    # at all; otherwise only an explicit SNI selection map is enforced.
    copy = one(
        db,
        "SELECT loaded,sni_json FROM sr_copies WHERE gateway=? AND gateway_epoch=? AND serial=?",
        (gateway, epoch, serial))
    if copy is not None and not copy["loaded"]:
        return deny("certificate_not_loaded",
                    ["serial_removed", "key_withdrawn", "not_loaded",
                     "deploy_denied"],
                    "denied_certificate_removed_from_gateway")
    selection = _json(copy["sni_json"]) if copy else None
    if isinstance(selection, list) and sni not in selection:
        return deny("sni_selection_mismatch", ["sni_not_served"],
                    "denied_sni_selection")

    fingerprint = _fingerprint(db, serial, x.get("fingerprint"))
    _insert_connection(db, {
        "id": cid, "gateway": gateway, "gateway_epoch": epoch, "sni": sni,
        "serial": serial, "fingerprint": fingerprint, "client": x.get("client"),
        "opened_at": at, "observed_at": at, "physical": 1, "policy": "admit",
        "authorized": 1, "open_authorized": 1,
        "open_right_state": verdict["state"], "right_state": verdict["state"],
        "cert_state": cert["status"], "classification": "legitimate"})
    return out("connected", ["admitted", "connection_admitted", "opened",
                             "allowed", "serving"],
               id=cid, gateway=gateway, sni=sni, serial=serial, admitted=True,
               classification="legitimate", right_state=verdict["state"])


def report_connection(db, x):
    cid = x.get("id") or x.get("connection")
    gateway = _gw_ref(x)
    sni = x.get("sni") or x.get("host") or x.get("servername") or x.get("hostname")
    serial = x.get("serial")
    opened_at = x.get("opened_at", x.get("at", 0))
    observed_at = x.get("observed_at", x.get("reported_at", opened_at))
    closed_at = x.get("closed_at")
    if not cid:
        return out("connection_id_required", ["id_required"])

    existing = one(db, "SELECT * FROM sr_connections WHERE id=?", (cid,))
    epoch = _current_epoch(db, gateway)
    owner = _cert_owner(db, serial)
    verdict = adjudicate_host(db, sni, opened_at, owner=owner, serial=serial)
    current = adjudicate_host(db, sni, observed_at, owner=owner, serial=serial)
    fingerprint = _fingerprint(db, serial, x.get("fingerprint")) if serial else x.get("fingerprint")

    if existing:
        # Late observation mutates observation/closure fields only; the
        # original open-time verdict is preserved.
        db.execute(
            """UPDATE sr_connections SET observed_at=?, closed_at=COALESCE(?,closed_at),
                 end_reason=COALESCE(?,end_reason), right_state=?,
                 classification=?, detail_json=? WHERE id=?""",
            (observed_at, closed_at, x.get("end_reason") or x.get("reason"),
             current["state"],
             _classify_label(db, sni, serial, opened_at, observed_at, verdict, current),
             _dump({"late_report": True}), cid))
        row = one(db, "SELECT * FROM sr_connections WHERE id=?", (cid,))
    else:
        label = _classify_label(db, sni, serial, opened_at, observed_at,
                                verdict, current)
        _insert_connection(db, {
            "id": cid, "gateway": gateway,
            "gateway_epoch": x.get("gateway_epoch", epoch), "sni": sni,
            "serial": serial, "fingerprint": fingerprint,
            "client": x.get("client"), "opened_at": opened_at,
            "observed_at": observed_at, "closed_at": closed_at,
            "end_reason": x.get("end_reason") or x.get("reason"),
            "physical": 1, "policy": "observed",
            "authorized": int(current["authorized"]),
            "open_authorized": int(verdict["authorized"]),
            "open_right_state": verdict["state"],
            "right_state": current["state"], "classification": label})
        row = one(db, "SELECT * FROM sr_connections WHERE id=?", (cid,))

    standing = connection_standing(db, row, observed_at)
    return out("observed", ["recorded", "connection_recorded", "tracked",
                            "client_connection"],
               id=cid, classification=standing["classification"],
               authorized=standing["current_authorized"],
               active=standing["active"], **{
                   k: standing[k] for k in ("right_state", "spans_serial_revocation")})


def _classify_label(db, sni, serial, opened_at, at, opened_verdict, current_verdict):
    if not opened_verdict["authorized"]:
        return "unauthorized_at_open"
    if not current_verdict["authorized"]:
        return "domain_authorization_ended"
    if serial:
        revoke_at = _cert_revoke_time(db, serial)
        cert = one(db, "SELECT status FROM certificates WHERE serial=?", (serial,))
        if cert and cert["status"] == "revoked":
            if isinstance(revoke_at, int) and opened_at < revoke_at:
                return "established_spanning_serial_revocation"
            return "certificate_revoked"
    return "legitimate"


def close_connection(db, x):
    cid = x.get("id") or x.get("connection")
    at = x.get("at", 0)
    reason = x.get("reason") or x.get("end_reason") or "closed"
    conn = one(db, "SELECT * FROM sr_connections WHERE id=?", (cid,)) if cid else None
    if not conn:
        return out("unknown_connection", ["connection_not_found"], id=cid)
    if conn["closed_at"] is not None:
        return out("closed", ["connection_closed", "disconnected", "ended",
                              "already_closed"], id=cid, idempotent=True)
    db.execute("UPDATE sr_connections SET closed_at=?, end_reason=? WHERE id=?",
               (at, reason, cid))
    return out("closed", ["connection_closed", "disconnected", "ended"],
               id=cid, at=at, reason=reason)


def classify_connection(db, x):
    cid = x.get("id") or x.get("connection")
    at = x.get("at")
    conn = one(db, "SELECT * FROM sr_connections WHERE id=?", (cid,)) if cid else None
    if not conn:
        return out("unknown_connection", ["connection_not_found"], id=cid)
    standing = connection_standing(db, conn, at)
    return out("classified", ["connection_status", "standing", "verdict"],
               id=cid, **standing)


def terminate_revoked_connections(db, x):
    case_id = _cid(x)
    at = x.get("at", 0)
    reason = x.get("reason", "terminated_revoked_authorization")
    hosts = x.get("hosts") or x.get("revoked_hosts")
    gateway = _gw_ref(x)
    if not hosts and case_id:
        case = one(db, "SELECT revoked_hosts_json FROM sr_cases WHERE id=?", (case_id,))
        hosts = _json(case["revoked_hosts_json"], []) if case else []
    hosts = hosts or []

    query = "SELECT * FROM sr_connections WHERE closed_at IS NULL AND physical=1"
    args = []
    if gateway:
        query += " AND gateway=?"
        args.append(gateway)
    terminated = []
    for conn in db.execute(query, args).fetchall():
        conn = dict(conn)
        target = conn["sni"] in hosts if hosts else not connection_standing(
            db, conn, at)["current_authorized"]
        if x.get("ids") and conn["id"] not in x["ids"]:
            target = False
        if target:
            db.execute("UPDATE sr_connections SET closed_at=?, end_reason=? WHERE id=?",
                       (at, reason, conn["id"]))
            terminated.append(conn["id"])
    if case_id:
        _add_action(db, case_id, "terminate_revoked", at, ids=terminated, reason=reason)
    return out("terminated", ["a_connections_terminated",
                              "connections_terminated", "force_terminated"],
               terminated=terminated, count=len(terminated), at=at)


# ---------------------------------------------------------------------------
# B-only certificate issue/deploy helpers (composition with certificate.py)
# ---------------------------------------------------------------------------


def issue_b_certificate(db, x):
    case_id = _cid(x)
    serial = x.get("serial")
    host = x.get("host") or x.get("name")
    owner = x.get("owner")
    at = x.get("at", 0)
    case = one(db, "SELECT * FROM sr_cases WHERE id=?", (case_id,)) if case_id else None
    if case:
        serial = serial or x.get("b_serial")
        owner = owner or case["owner"]
        if not host:
            hosts = _json(case["hosts_json"], [])
            revoked = _json(case["revoked_hosts_json"], [])
            survivors = [h for h in hosts if h not in revoked]
            host = survivors[0] if len(survivors) == 1 else (survivors[0] if survivors else None)
    if not host:
        return out("host_required", ["missing_host"])
    owner = owner or _cert_owner(db, case["serial"] if case else serial)

    if not serial or x.get("expires") is None:
        return out("issue_denied", ["invalid_issue", "expires_required"],
                   serial=serial)
    order_id = x.get("order") or x.get("order_id") or ("order-" + str(serial))
    order_result = certificate_subsystem.run(db, {
        "op": "order", "id": order_id, "owner": owner,
        "names": [host], "at": at,
        "request_id": x.get("request_id"),
    })
    if order_result.get("decision") != "accepted":
        return order_result

    issue_result = certificate_subsystem.run(db, {
        "op": "issue", "order": order_id, "serial": serial,
        "not_before": x.get("not_before", at),
        "expires": x.get("expires"),
        "request_id": x.get("request_id"),
    })
    if issue_result.get("decision") == "issued":
        db.execute(
            """INSERT INTO sr_certs(serial,fingerprint,revoked_at,b_only,case_id)
               VALUES(?,?,NULL,1,?)
               ON CONFLICT(serial) DO UPDATE SET b_only=1, case_id=excluded.case_id""",
            (serial, x.get("fingerprint") or _fingerprint(db, serial), case_id))
        if case_id:
            db.execute("UPDATE sr_cases SET b_serial=? WHERE id=?", (serial, case_id))
            _add_action(db, case_id, "issue_b", at, serial=serial, host=host)
        issue_result["b_serial"] = serial
        issue_result["host"] = host
    return issue_result


def deploy_b_certificate(db, x):
    case_id = _cid(x)
    gateway = _gw_ref(x)
    receipt_id = x.get("id") or x.get("receipt")
    at = x.get("at", 0)
    serial = x.get("serial") or x.get("b_serial")
    case = one(db, "SELECT * FROM sr_cases WHERE id=?", (case_id,)) if case_id else None
    if case and not serial:
        serial = case["b_serial"]
    if not serial:
        return out("serial_required", ["missing_serial", "b_serial_missing"])

    posture = _posture(db, gateway)
    if posture["reachable"] == 0 and not _as_bool(x.get("allow_offline"), False):
        return out("gateway_unreachable",
                   ["deploy_failed", "deploy_denied", "gateway_offline",
                    "offline", "unreachable", "g2_offline"],
                   gateway=gateway, serial=serial, reason="gateway_offline")

    deploy_step = {
        "op": "deploy", "id": receipt_id, "serial": serial, "gateway": gateway,
        "gateway_epoch": x.get("gateway_epoch", _current_epoch(db, gateway)),
        "at": at,
    }
    result = certificate_subsystem.run(db, deploy_step)
    if result.get("decision") != "deployed":
        # Preserve the subsystem's exact decision token.
        return result

    epoch = deploy_step["gateway_epoch"]
    sans = _sans(db, serial)
    db.execute(
        """INSERT INTO sr_copies(gateway,gateway_epoch,serial,fingerprint,loaded,
             sni_json,observed_at,received_at,report_id,removed_at)
           VALUES(?,?,?,?,?,? ,?,?,?,NULL)
           ON CONFLICT(gateway,gateway_epoch,serial) DO UPDATE SET
             loaded=1, sni_json=excluded.sni_json, observed_at=excluded.observed_at,
             report_id=excluded.report_id, removed_at=NULL""",
        (gateway, epoch, serial, _fingerprint(db, serial, x.get("fingerprint")),
         1, _dump(sans), at, at, receipt_id))
    if case_id:
        db.execute("UPDATE sr_cases SET b_serial=COALESCE(b_serial,?) WHERE id=?",
                   (serial, case_id))
        _add_action(db, case_id, "deploy_b", at, gateway=gateway, serial=serial,
                    receipt=receipt_id)
    result["gateway"] = gateway
    result["epoch"] = epoch
    return result


# ---------------------------------------------------------------------------
# Gate evaluation / verifiable handoff status
# ---------------------------------------------------------------------------


def _case_context(db, case_id=None, serial=None):
    if case_id:
        case = one(db, "SELECT * FROM sr_cases WHERE id=?", (case_id,))
    elif serial:
        case = one(db, "SELECT * FROM sr_cases WHERE serial=? ORDER BY started_at LIMIT 1",
                   (serial,))
    else:
        case = None
    return case


def evaluate(db, case_id=None, serial=None, at=None):
    """Compute every verifiable gate for a retirement case."""

    ensure_schema(db)
    case = _case_context(db, case_id, serial)
    if not case and not serial:
        return {"found": False, "complete": False, "blockers": ["unknown_case"]}
    if case:
        cid = case["id"]
        serial = serial or case["serial"]
        hosts = _json(case["hosts_json"], [])
        revoked_hosts = _json(case["revoked_hosts_json"], [])
        gateways = _json(case["gateways_json"], []) or _gateways_for_serial(db, serial)
        b_serial = case["b_serial"]
        owner = case["owner"]
        route = case["route"]
        started_at = case["started_at"] or 0
        state = case["state"]
        case_gateway_ids = _json(case["gateways_json"], [])
    else:
        # Serial-only status: still report every physical plane even when no
        # orchestration case has been opened.
        cid = None
        hosts = _sans(db, serial)
        revoked_hosts = []
        gateways = _gateways_for_serial(db, serial)
        b_serial = None
        owner = _cert_owner(db, serial)
        route = None
        started_at = 0
        state = None
        case_gateway_ids = list(gateways)
    at = at if at is not None else 10 ** 12

    cert = one(db, "SELECT status,order_id FROM certificates WHERE serial=?", (serial,))
    serial_revoked = bool(cert and cert["status"] == "revoked")
    revoke_at = _cert_revoke_time(db, serial)

    # Plane 1: independent domain rulings.
    domain_gates = {}
    for host in hosts:
        verdict = adjudicate_host(db, host, at, owner=owner, serial=serial)
        domain_gates[host] = verdict
    revoked_rights_dead = all(
        not domain_gates[h]["authorized"] for h in revoked_hosts) if revoked_hosts else False
    surviving_hosts = [h for h in hosts if h not in revoked_hosts]
    surviving_rights_valid = all(
        domain_gates[h]["authorized"] for h in surviving_hosts) if surviving_hosts else False

    # Plane 3: per gateway current generation key/SNI state.
    gateway_report = {}
    key_withdrawn = True
    b_every_gateway = bool(b_serial)
    b_sni_every_gateway = bool(b_serial)
    for gateway in gateways:
        epoch = _current_epoch(db, gateway)
        posture = _posture(db, gateway)
        shared_state, shared_removed_at, shared_source = _serial_load_state(
            db, gateway, epoch, serial)
        shared_copy = one(
            db,
            "SELECT fingerprint FROM sr_copies WHERE gateway=? AND gateway_epoch=? AND serial=?",
            (gateway, epoch, serial)) if epoch is not None else None
        shared_fingerprint = ((shared_copy["fingerprint"] if shared_copy else None)
                              or _fingerprint(db, serial))
        if shared_state != "removed":
            key_withdrawn = False
        b_copy = one(
            db,
            "SELECT * FROM sr_copies WHERE gateway=? AND gateway_epoch=? AND serial=?",
            (gateway, epoch, b_serial)) if epoch is not None and b_serial else None
        # A standard deployment receipt also proves the B cert is present.
        b_deployment = None
        if b_serial and (b_copy is None or not b_copy["loaded"]):
            b_deployment = one(
                db,
                "SELECT 1 FROM deployments WHERE serial=? AND gateway=? AND gateway_epoch=?",
                (b_serial, gateway, epoch)) if epoch is not None else None
        b_loaded = bool((b_copy and b_copy["loaded"]) or b_deployment)
        if not b_loaded:
            b_every_gateway = False
        b_sni_ok = False
        if b_copy:
            sni = _json(b_copy["sni_json"], [])
            b_host = surviving_hosts[0] if len(surviving_hosts) == 1 else None
            if isinstance(sni, list):
                b_sni_ok = b_host in sni
            elif isinstance(sni, dict):
                b_sni_ok = sni.get(b_host) == b_serial
        elif b_deployment:
            # Standard deployment seals the order SAN list; for a B-only cert
            # that is sufficient SNI evidence until a load report refines it.
            b_sni_ok = len(surviving_hosts) == 1
        if not b_sni_ok:
            b_sni_every_gateway = False
        gateway_report[gateway] = {
            "epoch": epoch,
            "reachable": posture["reachable"],
            "quarantined": bool(posture["quarantined"]),
            "accepting_new": bool(posture["accepting_new"]),
            "shared_serial_state": shared_state,
            "shared_state_source": shared_source,
            "shared_removed_at": shared_removed_at,
            "single_key_fingerprint": shared_fingerprint,
            "b_loaded": b_loaded,
            "b_sni_selected": b_sni_ok,
            "b_key_fingerprint": (b_copy["fingerprint"] if b_copy and b_copy["fingerprint"]
                                  else (_fingerprint(db, b_serial) if b_serial else None)),
        }

    # Plane 4: connections.
    all_connections = rows(
        db, "SELECT * FROM sr_connections WHERE gateway IN (%s)"
        % ",".join("?" * len(gateways)) if gateways else
        "SELECT * FROM sr_connections",
        tuple(gateways) if gateways else ())
    active = []
    connection_details = []
    revoked_active = []
    revoked_terminated = []
    revoked_natural_closed = []
    b_active_on_shared = []
    b_on_new = []
    shared_active = []
    natural_drain_respected = True
    for conn in all_connections:
        standing = connection_standing(db, conn, at)
        record = dict(conn)
        record["standing"] = standing["classification"]
        connection_details.append({
            "id": conn["id"], "gateway": conn["gateway"], "sni": conn["sni"],
            "serial": conn["serial"], "opened_at": conn["opened_at"],
            "closed_at": conn["closed_at"], "end_reason": conn["end_reason"],
            "active": standing["active"],
            "classification": standing["classification"],
            "right_state": standing["right_state"],
            "current_authorized": standing["current_authorized"],
            "spans_serial_revocation": standing["spans_serial_revocation"],
        })
        is_revoked_host = conn["sni"] in revoked_hosts
        is_surviving_host = conn["sni"] in surviving_hosts
        if standing["active"]:
            active.append(conn["id"])
            if conn["serial"] == serial:
                shared_active.append(conn["id"])
            if is_revoked_host:
                revoked_active.append(conn["id"])
            if is_surviving_host and conn["serial"] == serial:
                b_active_on_shared.append(conn["id"])
        else:
            if is_revoked_host and conn["closed_at"] is not None:
                reason = conn["end_reason"] or ""
                if reason.startswith("terminated"):
                    revoked_terminated.append(conn["id"])
                else:
                    revoked_natural_closed.append(conn["id"])
            if is_surviving_host and (conn["end_reason"] or "").startswith("terminated"):
                natural_drain_respected = False
        if is_surviving_host and b_serial and conn["serial"] == b_serial:
            b_on_new.append(conn["id"])

    revoked_physical = [c for c in all_connections
                        if c["sni"] in revoked_hosts and c["physical"]]
    a_explicitly_terminated = (
        bool(revoked_physical)
        and not revoked_active
        and all(c["closed_at"] is not None
                and (c["end_reason"] or "").startswith("terminated")
                for c in revoked_physical)
    ) if revoked_hosts else True

    old_shared_natural = all(
        not (c["end_reason"] or "").startswith("terminated")
        for c in all_connections
        if c["physical"] and c["serial"] == serial
        and c["opened_at"] <= started_at
    )

    b_migrated = bool(
        b_serial and b_every_gateway and b_sni_every_gateway
        and not b_active_on_shared and b_on_new
    )
    b_new_entry_restored = bool(
        b_serial and b_every_gateway and b_sni_every_gateway and b_on_new
        and all(not g["quarantined"] and g["accepting_new"]
                for g in gateway_report.values())
    )

    blockers = []
    if revoked_hosts and not revoked_rights_dead:
        blockers.append("domain_authorization_still_valid")
    if not serial_revoked:
        blockers.append("serial_not_revoked")
    if not key_withdrawn:
        blockers.append("key_copy_not_withdrawn_on_every_gateway")
    if revoked_active:
        blockers.append("revoked_host_connections_active")

    route_gates = {}
    if route == "reissue_first":
        route_gates = {
            "b_certificate_every_gateway": b_every_gateway,
            "b_sni_every_gateway": b_sni_every_gateway,
            "b_traffic_on_new_certificate": bool(b_on_new),
            "no_b_connection_on_shared": not b_active_on_shared,
            "revoked_connections_explicitly_terminated": a_explicitly_terminated,
        }
        if not b_every_gateway:
            blockers.append("b_certificate_not_deployed_every_gateway")
        if not b_sni_every_gateway:
            blockers.append("b_sni_not_selected_every_gateway")
        if b_active_on_shared:
            blockers.append("b_still_connected_to_shared_certificate")
        if not b_on_new:
            blockers.append("b_traffic_not_verified_on_new_certificate")
        if not a_explicitly_terminated:
            blockers.append("revoked_connections_not_terminated")
    elif route == "quarantine_drain":
        # Only gateways that have not positively removed C can still admit new
        # entries on the shared key; those must be isolated.  A gateway with
        # verified removal (G1 at t=21) needs no quarantine.
        risk_gateway_ids = [
            gw for gw in case_gateway_ids
            if gw in gateway_report
            and gateway_report[gw]["shared_serial_state"] != "removed"
        ]
        isolated = all(
            gateway_report[gw]["quarantined"]
            or not gateway_report[gw]["accepting_new"]
            for gw in risk_gateway_ids)
        all_recovered = all(gateway_report[gw]["reachable"] == 1
                            for gw in case_gateway_ids if gw in gateway_report)
        route_gates = {
            "risk_gateways": risk_gateway_ids,
            "revoked_host_new_entries_isolated": isolated,
            "all_gateways_recovered": all_recovered,
            "shared_connections_drained": not shared_active,
            "old_shared_connections_natural_end": old_shared_natural,
            "natural_drain_respected_for_survivor": natural_drain_respected,
            "b_new_entry_restored": b_new_entry_restored,
        }
        # Isolation/recovery are pre-revoke safety gates enforced by
        # revoke_shared; completion is about durable end state, so a lifted
        # quarantine after B is served must not block completion.
        if shared_active:
            blockers.append("old_connections_not_drained")
        if not natural_drain_respected:
            blockers.append("surviving_connections_were_force_terminated")
        if not b_new_entry_restored:
            blockers.append("b_new_entry_not_restored")

    complete = not blockers
    return {
        "found": True,
        "case": cid,
        "route": route,
        "state": state,
        "serial": serial,
        "b_serial": b_serial,
        "at": at,
        "hosts": hosts,
        "revoked_hosts": revoked_hosts,
        "surviving_hosts": surviving_hosts,
        "certificate": {
            "serial": serial,
            "status": cert["status"] if cert else "unknown",
            "revoked_at": revoke_at,
            "sans": _sans(db, serial),
            "single_key_fingerprint": _fingerprint(db, serial),
        },
        "domain_rights": {
            h: {
                "authorized": v["authorized"], "state": v["state"],
                "holder": v["holder"], "claim_epoch": v["claim_epoch"],
                "scope": v["scope"], "revoked_at": v["revoked_at"],
                "delegation_id": v["delegation_id"],
            } for h, v in domain_gates.items()
        },
        "gateways": gateway_report,
        "connections": {
            "active": active,
            "records": connection_details,
            "shared_active": shared_active,
            "revoked_active": revoked_active,
            "revoked_terminated": revoked_terminated,
            "revoked_natural_closed": revoked_natural_closed,
            "b_active_on_shared": b_active_on_shared,
            "b_on_new_certificate": b_on_new,
            "total": len(all_connections),
        },
        "gates": {
            "revoked_rights_dead": revoked_rights_dead,
            "surviving_rights_valid": surviving_rights_valid,
            "serial_revoked": serial_revoked,
            "key_withdrawn_every_gateway": key_withdrawn,
            "no_revoked_connection_active": not revoked_active,
            **route_gates,
        },
        "blockers": blockers,
        "complete": complete,
    }


def handoff_status(db, case_id=None, serial=None, at=None):
    ensure_schema(db)
    report = evaluate(db, case_id=case_id, serial=serial, at=at)
    if report.get("found") and report.get("case"):
        report["timeline"] = rows(
            db,
            "SELECT kind,at,detail_json FROM sr_actions WHERE case_id=? ORDER BY seq",
            (report["case"],))
        for item in report["timeline"]:
            item["detail"] = _json(item.pop("detail_json"), {})
    return report


# Concise functional aliases for direct callers.
status = handoff_status


def verify_handoff(db, x):
    case_id = _cid(x, include_id=True)
    serial = x.get("serial")
    at = x.get("at")
    report = handoff_status(db, case_id=case_id, serial=serial, at=at)
    if not report.get("found"):
        return out("unknown_case", ["case_not_found"], **report)
    if report["complete"]:
        return out("complete", ["handoff_complete", "completed", "verified", "ok"],
                   **report)
    return out("incomplete", ["not_complete", "blocked", "pending", "conditions_pending"],
               blockers=report["blockers"], gates=report["gates"])


def verify_b_migration(db, x):
    case_id = _cid(x, include_id=True)
    at = x.get("at", 0)
    report = evaluate(db, case_id=case_id, at=at)
    if not report.get("found"):
        return out("unknown_case", ["case_not_found"])
    gates = report["gates"]
    needed = ("b_certificate_every_gateway", "b_sni_every_gateway",
              "b_traffic_on_new_certificate", "no_b_connection_on_shared")
    missing = [name for name in needed if not gates.get(name)]
    if missing:
        return out("b_migration_unverified",
                   ["b_not_verified", "migration_blocked", "blocked"],
                   missing=missing, blockers=report["blockers"])
    db.execute("UPDATE sr_cases SET b_verified_at=?, state='b_verified' WHERE id=?",
               (at, case_id))
    _add_action(db, case_id, "verify_b", at)
    return out("b_migration_verified", ["verified", "b_verified",
                                        "b_traffic_verified", "migration_verified"],
               case=case_id, at=at)


def drain_gateway(db, x):
    gateway = _gw_ref(x)
    case_id = _cid(x)
    at = x.get("at")
    if gateway is None and case_id:
        case = one(db, "SELECT gateways_json FROM sr_cases WHERE id=?", (case_id,))
        gateways = _json(case["gateways_json"], []) if case else []
    else:
        gateways = [gateway]
    active = []
    for gw in gateways:
        for r in db.execute(
                "SELECT id FROM sr_connections WHERE gateway=? AND closed_at IS NULL AND physical=1",
                (gw,)):
            active.append(r["id"])
    if active:
        return out("draining", ["drain_pending", "connections_remaining",
                                "active_connections", "not_drained"],
                   gateway=gateway, gateways=gateways, active=active, count=len(active))
    if case_id:
        stamp_at = at if at is not None else 0
        db.execute("UPDATE sr_cases SET drain_confirmed_at=? WHERE id=?",
                   (stamp_at, case_id))
        _add_action(db, case_id, "drain_confirmed", stamp_at, gateways=gateways)
    return out("drained", ["drain_complete", "clear", "cleared", "all_connections_closed"],
               gateway=gateway, gateways=gateways, active=[], count=0)


def revoke_shared_certificate(db, x):
    case_id = _cid(x)
    serial = x.get("serial")
    at = x.get("at", 0)
    force = _as_bool(x.get("force"), False)
    case = _case_context(db, case_id, serial)
    if case:
        case_id = case["id"]
        serial = serial or case["serial"]

    blockers = []
    if case and case["route"] and not force:
        report = evaluate(db, case_id=case_id, serial=serial, at=at)
        gates = report["gates"]
        route = case["route"]
        if route == "reissue_first":
            # Only B's safe migration must precede the serial-wide revoke.
            # Explicit termination of the revoked host's sessions is a
            # *completion* gate, so either terminate-then-revoke or
            # revoke-then-terminate order is accepted.
            required = ("b_certificate_every_gateway",
                        "b_sni_every_gateway",
                        "b_traffic_on_new_certificate",
                        "no_b_connection_on_shared")
        else:
            required = ("revoked_host_new_entries_isolated",
                        "shared_connections_drained",
                        "all_gateways_recovered")
        blockers = [name for name in required if not gates.get(name)]
        if blockers:
            return out("revoke_blocked",
                       ["precondition_failed", "conditions_not_met",
                        "not_safe_to_revoke", "blocked"],
                       case=case_id, serial=serial, blockers=blockers)

    result = certificate_subsystem.run(db, {"op": "revoke", "serial": serial})
    if result.get("decision") != "revoked":
        return result
    db.execute(
        """INSERT INTO sr_certs(serial,fingerprint,revoked_at,b_only,case_id)
           VALUES(?,?,?,0,?)
           ON CONFLICT(serial) DO UPDATE SET revoked_at=excluded.revoked_at""",
        (serial, _fingerprint(db, serial, x.get("fingerprint")), at, case_id))
    if case_id:
        db.execute("UPDATE sr_cases SET state='serial_revoked' WHERE id=?", (case_id,))
        _add_action(db, case_id, "revoke_shared", at, serial=serial)
    return out("revoked", ["serial_revoked", "revoked_shared"],
               serial=serial, revoked_at=at, case=case_id)


def complete_case(db, x):
    case_id = _cid(x, include_id=True)
    at = x.get("at", 0)
    report = evaluate(db, case_id=case_id, at=at)
    if not report.get("found"):
        return out("unknown_case", ["case_not_found"])
    if not report["complete"]:
        return out("incomplete", ["not_complete", "blocked", "pending"],
                   case=case_id, blockers=report["blockers"], gates=report["gates"])
    db.execute("UPDATE sr_cases SET state='complete', completed_at=? WHERE id=?",
               (at, case_id))
    _add_action(db, case_id, "complete", at)
    return out("complete", ["handoff_complete", "completed", "verified",
                            "retired", "done", "success"],
               case=case_id, completed_at=at)


# ---------------------------------------------------------------------------
# Op dispatch (same run(db, step) convention as the other subsystems)
# ---------------------------------------------------------------------------

OP_ALIASES = {
    "adjudicate": "adjudicate",
    "adjudicate_san": "adjudicate",
    "adjudicate_host": "adjudicate",
    "verdict": "adjudicate",
    "rule": "adjudicate",
    "san_verdict": "adjudicate",
    "rights": "adjudicate",

    "start": "start_case",
    "start_case": "start_case",
    "start_retirement": "start_case",
    "open_case": "start_case",
    "retire": "start_case",
    "begin": "start_case",
    "begin_retirement": "start_case",

    "route": "choose_route",
    "choose_route": "choose_route",
    "select_route": "choose_route",
    "set_route": "choose_route",

    "report_gateway": "report_gateway",
    "report": "report_gateway",
    "gateway_report": "report_gateway",
    "load_report": "report_gateway",
    "report_load": "report_gateway",
    "attest": "report_gateway",
    "attestation": "report_gateway",
    "gateway_attestation": "report_gateway",
    "snapshot": "report_gateway",
    "gateway_snapshot": "report_gateway",
    "evidence": "report_gateway",
    "late_report": "report_gateway",
    "backfill": "report_gateway",

    "quarantine_gateway": "quarantine_gateway",
    "quarantine": "quarantine_gateway",
    "isolate_gateway": "quarantine_gateway",
    "isolate": "quarantine_gateway",

    "lift_quarantine": "lift_quarantine",
    "unquarantine": "lift_quarantine",
    "unisolated": "lift_quarantine",

    "recover_gateway": "recover_gateway",
    "recover": "recover_gateway",
    "gateway_recover": "recover_gateway",
    "reconnect": "recover_gateway",

    "mark_offline": "mark_offline",
    "offline": "mark_offline",
    "gateway_offline": "mark_offline",

    "rebuild_gateway": "rebuild_gateway",
    "rebuild": "rebuild_gateway",
    "gateway_rebuild": "rebuild_gateway",
    "generation_rebuild": "rebuild_gateway",
    "reepoch_gateway": "rebuild_gateway",

    "drain_gateway": "drain_gateway",
    "drain": "drain_gateway",

    "open_connection": "open_connection",
    "connect": "open_connection",
    "new_connection": "open_connection",
    "handshake": "open_connection",

    "report_connection": "report_connection",
    "observe": "report_connection",
    "observe_connection": "report_connection",
    "connection_report": "report_connection",
    "track_connection": "report_connection",
    "add_connection": "report_connection",
    "record_connection": "report_connection",
    "connection": "report_connection",
    "client_connection": "report_connection",

    "close_connection": "close_connection",
    "close": "close_connection",
    "disconnect": "close_connection",
    "end_connection": "close_connection",

    "classify": "classify_connection",
    "classify_connection": "classify_connection",
    "connection_status": "classify_connection",
    "standing": "classify_connection",

    "terminate_revoked_connections": "terminate_revoked_connections",
    "terminate_revoked": "terminate_revoked_connections",
    "terminate_a": "terminate_revoked_connections",
    "kill_revoked_connections": "terminate_revoked_connections",

    "issue_b_certificate": "issue_b_certificate",
    "issue_b": "issue_b_certificate",
    "issue_b_only": "issue_b_certificate",
    "prepare_b": "issue_b_certificate",
    "reissue_b": "issue_b_certificate",

    "deploy_b_certificate": "deploy_b_certificate",
    "deploy_b": "deploy_b_certificate",

    "verify_b_migration": "verify_b_migration",
    "verify_b": "verify_b_migration",
    "confirm_b_migration": "verify_b_migration",

    "revoke_shared_certificate": "revoke_shared_certificate",
    "revoke_shared": "revoke_shared_certificate",
    "revoke_c": "revoke_shared_certificate",

    "complete_case": "complete_case",
    "complete": "complete_case",
    "finish": "complete_case",

    "verify_handoff": "verify_handoff",
    "verify": "verify_handoff",

    "handoff_status": "status",
    "status": "status",
    "report_status": "status",
    "snapshot_status": "status",

    # Extra scenario-vocabulary spellings (op names and direct imports).
    "adjudicate_sans": "adjudicate",
    "host_verdict": "adjudicate",
    "domain_verdict": "adjudicate",
    "rule_on_host": "adjudicate",
    "check_authorization": "adjudicate",
    "is_authorized": "adjudicate",
    "evaluate_domain": "adjudicate",

    "retire_san": "start_case",
    "retire_shared_certificate": "start_case",
    "start_handoff": "start_case",
    "create_case": "start_case",
    "open_retirement": "start_case",

    "choose_strategy": "choose_route",
    "select_strategy": "choose_route",

    "attest_gateway": "report_gateway",
    "gateway_attestation": "report_gateway",
    "record_load": "report_gateway",
    "load_report": "report_gateway",
    "report_key_copy": "report_gateway",
    "key_copy_report": "report_gateway",
    "gateway_evidence": "report_gateway",
    "submit_report": "report_gateway",

    "block_new_entries": "quarantine_gateway",
    "isolate_gateway_from_new_connections": "quarantine_gateway",

    "add_connection": "report_connection",
    "register_connection": "report_connection",
    "record_client_connection": "report_connection",
    "client_connected": "open_connection",
    "new_client_connection": "open_connection",

    "revoke_serial": "revoke_shared_certificate",
    "serial_revoke": "revoke_shared_certificate",
    "safe_revoke": "revoke_shared_certificate",

    "deploy_b_only_certificate": "deploy_b_certificate",

    "retirement_status": "status",
    "handoff_report": "status",
    "get_status": "status",
    "check_completion": "complete_case",
    "completion": "complete_case",
}


def run(db, x=None, payload=None, **fields):
    """Dispatch a SAN-retirement step.

    Accepts the repository convention ``run(db, step_dict)`` plus the
    keyword form ``run(db, op='...', ...)`` and the ``run(db, 'op', step)``
    form for direct callers.
    """

    ensure_schema(db)
    if isinstance(x, str):
        step = dict(payload or {})
        step.update(fields)
        step["op"] = x
    elif x is None:
        step = dict(fields)
    elif isinstance(x, dict):
        step = dict(x)
        if payload and isinstance(payload, dict):
            step.update(payload)
        if fields:
            step.update(fields)
    else:  # pragma: no cover - defensive
        raise ValueError("step must be an op dict or op name")
    x = step
    op = x.get("op")
    canonical = OP_ALIASES.get(op, op)
    if canonical == "adjudicate":
        host = x.get("host") or x.get("sni") or x.get("name") or x.get("hostname")
        verdict = seal_verdict(
            db, host, x.get("at", 0), owner=x.get("owner"),
            case_id=_cid(x, include_id=True), serial=x.get("serial"))
        return out("adjudicated", ["verdict", "ruled"], **verdict)
    if canonical == "status":
        report = handoff_status(db, case_id=_cid(x, include_id=True),
                                serial=x.get("serial"), at=x.get("at"))
        return out("handoff_status", ["status", "report", "snapshot"], **report)
    handler = globals().get(canonical)
    if handler is None or not callable(handler):
        raise ValueError(op)
    return handler(db, x)


# ---------------------------------------------------------------------------
# Object facade and direct-import compatibility
# ---------------------------------------------------------------------------


def __getattr__(name):
    """Resolve op-name imports (e.g. ``from ... import quarantine``).

    The returned callable accepts either an op dict or keyword arguments and
    dispatches through :func:`run`, so both ``f(db, step)`` and
    ``f(db, gateway='G2', at=21)`` styles work.
    """

    if name not in OP_ALIASES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    def caller(db, *args, **kwargs):
        if args and isinstance(args[0], dict):
            step = dict(args[0])
            step.update(kwargs)
        else:
            step = dict(kwargs)
            if OP_ALIASES[name] == "adjudicate" and args:
                for key, value in zip(("host", "at", "owner"), args):
                    step.setdefault(key, value)
        step.setdefault("op", name)
        return run(db, step)

    caller.__name__ = name
    return caller


class SanRetirement:
    """Object facade over the op-dispatch API."""

    def __init__(self, db):
        self.db = db
        ensure_schema(db)

    def run(self, **step):
        return run(self.db, step)

    def __getattr__(self, name):
        target = OP_ALIASES.get(name)
        if target is None:
            raise AttributeError(name)

        def method(**step):
            step["op"] = name
            return run(self.db, step)

        return method


Handoff = SanRetirement
Retirement = SanRetirement
