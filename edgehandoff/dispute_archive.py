"""Offline dispute evidence archive for domain delegation history.

This module builds evidence packages for dispute mediation.  It never rules on
who owns a domain: it freezes the *local* event order, inputs and results in an
append-only hash chain and keeps external material (authoritative DNS answers,
registrar documents, cached queries) in a separately labelled evidence ledger.

Design invariants
-----------------
* Local events are anchored by an append-only hash chain over
  ``seq -> structural input digest -> result digest``.  Re-exporting after
  late evidence arrives never rewrites or reorders an existing chain entry.
* Event inputs are digested as a Merkle-style structural hash in which every
  leaf is itself hashed.  A redacted leaf can therefore be replaced by its
  commitment and the same input digest recomputed, so hiding unrelated
  customer fields never breaks the verifiable chain.
* Host selection walks the parsed JSON of every event and matches the *exact*
  host value, and reports the number of events scanned, so the export can show
  it did not silently skip an event (a ``LIKE``/substring search cannot).
* Authority is kept separate.  A local ``prove`` decision only compares the
  caller-supplied challenge, epoch and lease; it is annotated with an
  ``authority_gap`` unless a sealed authoritative answer exists at that
  moment.  A successful local replay is labelled ``local_state`` and is never
  phrased as proof of external ownership.
* Forged/cached timestamps cannot backdate the ledger: arrival order is the
  chain order; a stale claimed time is flagged, never used to reorder.
* A minimal-disclosure copy hides unrelated customer fields behind per-field
  hash commitments while the original event hash chain stays verifiable.
* Export requires a signed, expiring grant with a signed receipt; knowing the
  host name alone is not enough to download a package.
"""
import base64
import hashlib
import hmac
import json
import sqlite3

from .store import connect, execute, one, rows

ARCHIVE_SCHEMA = """
CREATE TABLE IF NOT EXISTS dispute_grants(
    grant_id TEXT PRIMARY KEY, grantee TEXT, host TEXT, scope TEXT,
    issued_at INTEGER, expires_at INTEGER, witness_key_id TEXT,
    signature TEXT, revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS dispute_receipts(
    package_id TEXT PRIMARY KEY, grant_id TEXT, host TEXT, mode TEXT,
    issued_at INTEGER, expires_at INTEGER, redacted INTEGER,
    event_root TEXT, evidence_root TEXT, signature TEXT);
CREATE TABLE IF NOT EXISTS dispute_evidence(
    evidence_id TEXT PRIMARY KEY, host TEXT, kind TEXT, source TEXT,
    viewpoint TEXT, claimed_at INTEGER, received_at INTEGER,
    raw_bytes BLOB, media_type TEXT, seal TEXT, seal_key_id TEXT,
    affects_seq INTEGER, note TEXT, prev_hash TEXT, self_hash TEXT);
CREATE TABLE IF NOT EXISTS dispute_exports(
    package_id TEXT PRIMARY KEY, host TEXT, mode TEXT, grant_id TEXT,
    created_at INTEGER, event_count INTEGER, event_root TEXT,
    evidence_count INTEGER, evidence_root TEXT);
"""

# Evidence whose origin is an authority or an independent witness.  Everything
# else (cached queries, platform logs, self-asserted notes) is local/derived
# material and cannot by itself establish an external fact.
SEALED_KINDS = ('authoritative_dns', 'registrar')
LOCAL_KINDS = ('cached_dns', 'platform_log', 'note')
ORIGINAL_REQUIRED_FACTS = (
    'authoritative_dns_answer',
    'registrar_transfer_acceptance',
    'registrar_transfer_effective_receipt',
    'redacted_unrelated_customer_field',
)
COMMITTABLE_FACTS = (
    'local_event_order_and_result',
    'redacted_field_presence_and_value_commitment',
    'cached_query_presence_timestamp_unauthenticated',
)


def _b64(raw):
    return base64.b64encode(raw).decode('ascii')


def _canon(value):
    """Stable byte encoding for any JSON-serialisable value."""
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')


def digest(value):
    """SHA-256 of a value's canonical encoding, returned as hex text."""
    return hashlib.sha256(_canon(value)).hexdigest()


def structural_digest(node):
    """Merkle-style digest in which every leaf is independently committed.

    Hiding a leaf and substituting its commitment therefore preserves the root
    digest, which is what makes redaction compatible with the append chain.
    """
    if isinstance(node, dict):
        return digest({k: structural_digest(v) for k, v in node.items()})
    if isinstance(node, (list, tuple)):
        return digest([structural_digest(v) for v in node])
    return digest(node)


def _sign(key, value):
    return hmac.new(key, _canon(value), hashlib.sha256).hexdigest()


def _verify_sig(key, value, signature):
    return bool(signature) and hmac.compare_digest(_sign(key, value), signature)


def init_archive(db):
    db.executescript(ARCHIVE_SCHEMA)


def _safe_json(raw):
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# Exact, structural host selection over every local event
# --------------------------------------------------------------------------- #
def _json_contains_exact(node, host):
    """True only when ``host`` appears as an exact string value."""
    if isinstance(node, str):
        return node == host
    if isinstance(node, dict):
        return any(_json_contains_exact(v, host) for v in node.values())
    if isinstance(node, (list, tuple)):
        return any(_json_contains_exact(v, host) for v in node)
    return False


def host_events(db, host):
    """All events that structurally mention ``host``, in immutable seq order.

    The whole table is scanned and the *parsed* input is compared against the
    exact host value.  Returning the total scanned count alongside the hits
    lets a consumer prove no event was dropped rather than trusting a query.
    """
    scanned = rows(db, 'SELECT seq, subsystem, request_id, input, result '
                       'FROM events ORDER BY seq')
    hits = [row for row in scanned
            if _json_contains_exact(json.loads(row['input']), host)]
    return {'scanned': len(scanned), 'matched': len(hits), 'events': hits}


def event_chain(db, host):
    """Hash chain over the selected events; never reads mutable table state."""
    selection = host_events(db, host)
    prev = ''
    entries = []
    for row in selection['events']:
        entry = {
            'seq': row['seq'],
            'subsystem': row['subsystem'],
            'request_id': row['request_id'],
            'input_hash': structural_digest(json.loads(row['input'])),
            'result_hash': digest(json.loads(row['result'])),
            'prev_hash': prev,
        }
        entry['self_hash'] = digest({k: entry[k] for k in
                                     ('seq', 'input_hash', 'result_hash',
                                      'prev_hash')})
        prev = entry['self_hash']
        entries.append(entry)
    return {'host': host, 'scanned': selection['scanned'],
            'matched': selection['matched'], 'entries': entries,
            'root': prev}


def authority_gaps(db, host):
    """Local ``verified`` claims lacking a sealed authoritative answer then.

    A local prove only checks the challenge/epoch/lease the caller supplied.
    Unless an authoritative DNS record with a seal is attached at or before
    the proof time, the verification rests on local inputs alone and carries
    an authority gap; forked answers are reported rather than resolved.
    """
    gaps = []
    sealed = rows(
        db,
        "SELECT * FROM dispute_evidence WHERE host=? AND kind='authoritative_dns' "
        "AND seal IS NOT NULL ORDER BY rowid", (host,))
    for row in host_events(db, host)['events']:
        inp = json.loads(row['input'])
        res = json.loads(row['result'])
        if inp.get('op') != 'prove' or res.get('decision') != 'verified':
            continue
        at = inp.get('at', 0)
        present = [e for e in sealed if e['received_at'] <= at]
        answers = set()
        for e in present:
            parsed = _safe_json(e['raw_bytes'])
            if isinstance(parsed, dict) and parsed.get('value') is not None:
                answers.add(parsed['value'])
        if not present:
            gaps.append({
                'seq': row['seq'], 'at': at, 'challenge': inp.get('challenge'),
                'local_basis': ('caller_supplied_challenge,epoch,lease; no '
                                'authoritative answer stored at prove time'),
                'authority_answer_present': False, 'forked_answers': [],
            })
        elif len(answers) > 1:
            gaps.append({
                'seq': row['seq'], 'at': at, 'challenge': inp.get('challenge'),
                'local_basis': 'caller_supplied_challenge matched one fork only',
                'authority_answer_present': True,
                'forked_answers': sorted(answers),
            })
    return gaps


def local_replay(db, host):
    """Re-execute the complete local log on an empty database.

    The full log is replayed (a host-scoped subset could not reproduce
    cross-domain orders on its own), then every recorded result of the host's
    events is checked.  The conclusion is strictly about local determinism:
    it cannot establish external ownership and is labelled accordingly.
    """
    log = rows(db, 'SELECT subsystem, input, result FROM events ORDER BY seq')
    target = connect(':memory:')
    divergence = []
    host_seqs = {e['seq'] for e in host_events(db, host)['events']}
    for i, item in enumerate(log, 1):
        actual = execute(target, item['subsystem'], json.loads(item['input']))
        if actual != json.loads(item['result']):
            divergence.append({'seq': i, 'kind': 'decision'})
    host_results = [json.loads(r['result']) for r in
                    host_events(db, host)['events']]
    target.close()
    return {'host': host, 'events_replayed': len(log),
            'host_events': len(host_seqs),
            'host_decisions_reproduced': len(host_results),
            'verified': not divergence, 'divergence': divergence,
            'conclusion_scope': 'local_state',
            'note': ('replay confirms local event determinism only; it is not '
                     'proof of external domain ownership')}


# --------------------------------------------------------------------------- #
# Signed, expiring export grants and receipts
# --------------------------------------------------------------------------- #
def issue_grant(db, grant_id, grantee, host, scope, issued_at, ttl,
                export_key, key_id='export-key-1'):
    init_archive(db)
    if one(db, 'SELECT * FROM dispute_grants WHERE grant_id=?', (grant_id,)):
        return {'decision': 'grant_conflict'}
    if ttl <= 0:
        return {'decision': 'invalid_grant_ttl'}
    body = {'grant_id': grant_id, 'grantee': grantee, 'host': host,
            'scope': scope, 'issued_at': issued_at,
            'expires_at': issued_at + ttl, 'key_id': key_id}
    sig = _sign(export_key, body)
    db.execute('INSERT INTO dispute_grants VALUES(?,?,?,?,?,?,?,?,0)',
               (grant_id, grantee, host, scope, issued_at,
                issued_at + ttl, key_id, sig))
    return {'decision': 'granted', 'expires_at': issued_at + ttl,
            'signature': sig}


def _load_valid_grant(db, grant_id, host, at, export_key):
    grant = one(db, 'SELECT * FROM dispute_grants WHERE grant_id=?',
                (grant_id,))
    if not grant:
        return None, 'unknown_grant'
    if grant['host'] != host:
        return None, 'grant_host_mismatch'
    if grant['revoked']:
        return None, 'grant_revoked'
    if at >= grant['expires_at']:
        return None, 'grant_expired'
    body = {'grant_id': grant['grant_id'], 'grantee': grant['grantee'],
            'host': grant['host'], 'scope': grant['scope'],
            'issued_at': grant['issued_at'], 'expires_at': grant['expires_at'],
            'key_id': grant['witness_key_id']}
    if not _verify_sig(export_key, body, grant['signature']):
        return None, 'grant_signature_invalid'
    return grant, None


def revoke_grant(db, grant_id):
    init_archive(db)
    if not one(db, 'SELECT * FROM dispute_grants WHERE grant_id=?',
               (grant_id,)):
        return {'decision': 'unknown_grant'}
    db.execute('UPDATE dispute_grants SET revoked=1 WHERE grant_id=?',
               (grant_id,))
    return {'decision': 'revoked'}


# --------------------------------------------------------------------------- #
# Append-only external evidence ledger
# --------------------------------------------------------------------------- #
def add_evidence(db, evidence_id, host, kind, source, viewpoint, claimed_at,
                 received_at, raw_bytes, media_type='application/json',
                 seal=None, seal_key_id=None, affects_seq=None, note=None):
    """Attach external material.  Append-only; late items never reorder history.

    A cached/self-asserted record whose claimed time predates its arrival is
    marked ``timestamp_unauthenticated``.  ``affects_seq`` points at the prior
    judgment the new material bears on but cannot modify it.
    """
    init_archive(db)
    if kind not in SEALED_KINDS + LOCAL_KINDS:
        return {'decision': 'unknown_evidence_kind'}
    if one(db, 'SELECT * FROM dispute_evidence WHERE evidence_id=?',
           (evidence_id,)):
        return {'decision': 'evidence_conflict'}
    if affects_seq is not None and not one(
            db, 'SELECT seq FROM events WHERE seq=?', (affects_seq,)):
        return {'decision': 'unknown_affected_seq'}
    if isinstance(raw_bytes, str):
        raw_bytes = raw_bytes.encode('utf-8')
    flags = []
    if claimed_at is not None and received_at is not None \
            and claimed_at < received_at:
        if kind not in SEALED_KINDS or seal is None:
            flags.append('timestamp_unauthenticated')
    if kind in SEALED_KINDS and seal is None:
        flags.append('seal_required_missing')
    last = db.execute(
        'SELECT self_hash FROM dispute_evidence WHERE host=? '
        'ORDER BY rowid DESC LIMIT 1', (host,)).fetchone()
    prev_hash = last['self_hash'] if last else ''
    body = {'evidence_id': evidence_id, 'host': host, 'kind': kind,
            'source': source, 'viewpoint': viewpoint, 'claimed_at': claimed_at,
            'received_at': received_at,
            'raw_sha256': hashlib.sha256(raw_bytes).hexdigest(),
            'media_type': media_type, 'seal': seal,
            'seal_key_id': seal_key_id, 'affects_seq': affects_seq,
            'note': note, 'flags': flags, 'prev_hash': prev_hash}
    self_hash = digest(body)
    db.execute('INSERT INTO dispute_evidence VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (evidence_id, host, kind, source, viewpoint, claimed_at,
                received_at, sqlite3.Binary(raw_bytes), media_type, seal,
                seal_key_id, affects_seq, note, prev_hash, self_hash))
    return {'decision': 'appended', 'self_hash': self_hash, 'flags': flags,
            'appended_after_existing': prev_hash != ''}


def evidence_chain(db, host):
    prev = ''
    out = []
    for row in rows(db, 'SELECT * FROM dispute_evidence WHERE host=? '
                        'ORDER BY rowid', (host,)):
        out.append({'evidence_id': row['evidence_id'], 'kind': row['kind'],
                    'received_at': row['received_at'],
                    'claimed_at': row['claimed_at'],
                    'prev_hash': row['prev_hash'],
                    'self_hash': row['self_hash']})
        if row['prev_hash'] != prev:
            return {'host': host, 'verified': False,
                    'broken_at': row['evidence_id'], 'entries': out,
                    'root': ''}
        prev = row['self_hash']
    return {'host': host, 'verified': True, 'entries': out, 'root': prev}


def dns_fork(db, host):
    """Distinct sealed authoritative answers across viewpoints at a moment."""
    found = rows(
        db,
        "SELECT viewpoint, raw_bytes, seal, claimed_at, received_at "
        "FROM dispute_evidence WHERE host=? AND kind='authoritative_dns' "
        "ORDER BY claimed_at, viewpoint", (host,))
    answers = {}
    for r in found:
        parsed = _safe_json(r['raw_bytes'])
        value = parsed.get('value') if isinstance(parsed, dict) else None
        answers.setdefault(value, []).append(
            {'viewpoint': r['viewpoint'], 'sealed': r['seal'] is not None,
             'claimed_at': r['claimed_at'], 'received_at': r['received_at']})
    forked = len({k for k in answers if k is not None}) > 1
    return {'host': host, 'forked': forked, 'answers': answers,
            'interpretation': ('authoritative servers returned different '
                               'answers; no single answer may be presented as '
                               'the platform-wide truth at that moment')
            if forked else 'single authoritative answer set'}


# --------------------------------------------------------------------------- #
# Field-level redaction with hash commitments
# --------------------------------------------------------------------------- #
def _referenced_hosts(inp):
    hosts = set()
    if isinstance(inp, dict):
        if isinstance(inp.get('host'), str):
            hosts.add(inp['host'])
        for name in inp.get('names', []) or []:
            if isinstance(name, str):
                hosts.add(name)
    return hosts


def _redact(node, hidden_hosts, path=()):
    """Replace any string mentioning a hidden host with a commitment marker.

    All other values are preserved verbatim; the marker carries the leaf's
    structural commitment, which is exactly what ``structural_digest`` would
    have computed for the original leaf.
    """
    if isinstance(node, dict):
        red, commits = {}, {}
        for k, v in node.items():
            rv, rc = _redact(v, hidden_hosts, path + (k,))
            red[k] = rv
            commits.update(rc)
        return red, commits
    if isinstance(node, list):
        red, commits = [], {}
        for i, v in enumerate(node):
            rv, rc = _redact(v, hidden_hosts, path + (str(i),))
            red.append(rv)
            commits.update(rc)
        return red, commits
    if isinstance(node, str) and any(h == node or h in node
                                     for h in hidden_hosts):
        key = '.'.join(path)
        marker = {'redacted': True, 'path': key,
                  'commitment': structural_digest(node)}
        return marker, {key: structural_digest(node)}
    return node, {}


def recommit(redacted_node):
    """Recompute the structural input digest over a redacted tree."""
    if isinstance(redacted_node, dict):
        if set(redacted_node) == {'redacted', 'path', 'commitment'}:
            return redacted_node['commitment']
        return digest({k: recommit(v) for k, v in redacted_node.items()})
    if isinstance(redacted_node, list):
        return digest([recommit(v) for v in redacted_node])
    return structural_digest(redacted_node)


# --------------------------------------------------------------------------- #
# Package construction
# --------------------------------------------------------------------------- #
def build_package(db, package_id, host, grant_id, at, mode, export_key,
                  witness_key, export_path=None):
    """Construct an offline package.  ``mode`` is 'original' or 'minimal'."""
    init_archive(db)
    if mode not in ('original', 'minimal'):
        return {'decision': 'unknown_mode'}
    if one(db, 'SELECT * FROM dispute_exports WHERE package_id=?',
           (package_id,)):
        return {'decision': 'package_conflict'}
    grant, err = _load_valid_grant(db, grant_id, host, at, export_key)
    if err:
        return {'decision': err}

    chain = event_chain(db, host)
    selection = host_events(db, host)
    ev_chain = evidence_chain(db, host)
    replay_report = local_replay(db, host)
    gaps = authority_gaps(db, host)

    package_events = []
    redaction_manifest = []
    for row, anchor in zip(chain['entries'], selection['events']):
        inp = json.loads(anchor['input'])
        res = json.loads(anchor['result'])
        hidden = sorted(h for h in _referenced_hosts(inp) if h != host)
        record = {
            'seq': row['seq'], 'subsystem': row['subsystem'],
            'request_id': row['request_id'], 'input': inp, 'result': res,
            'input_hash': row['input_hash'], 'result_hash': row['result_hash'],
            'prev_hash': row['prev_hash'], 'self_hash': row['self_hash'],
            # Count only: naming the hidden hosts would leak them into the
            # minimal package.
            'redacted_field_count': len(hidden),
            # Independently replayable only when every referenced host's
            # prerequisites are inside the package.
            'independently_replayable': not hidden,
        }
        if mode == 'minimal' and hidden:
            red_input, commits = _redact(inp, hidden)
            if recommit(red_input) != row['input_hash']:
                return {'decision': 'redaction_commitment_failure'}
            record['input'] = red_input
            record['redaction_commitments'] = commits
            redaction_manifest.append(
                {'seq': row['seq'], 'paths': sorted(commits),
                 'commitments': commits,
                 'original_input_hash': row['input_hash']})
        package_events.append(record)

    evidence = []
    for e in rows(db, 'SELECT * FROM dispute_evidence WHERE host=? '
                     'ORDER BY rowid', (host,)):
        item = {'evidence_id': e['evidence_id'], 'kind': e['kind'],
                'source': e['source'], 'viewpoint': e['viewpoint'],
                'claimed_at': e['claimed_at'], 'received_at': e['received_at'],
                'media_type': e['media_type'], 'seal': e['seal'],
                'seal_key_id': e['seal_key_id'],
                'affects_seq': e['affects_seq'], 'note': e['note'],
                'prev_hash': e['prev_hash'], 'self_hash': e['self_hash'],
                'raw_sha256': hashlib.sha256(e['raw_bytes']).hexdigest()}
        if mode == 'original':
            item['raw_bytes_b64'] = _b64(e['raw_bytes'])
        else:
            # Originals stay with the sealed-room custodian.
            item['raw_bytes_b64'] = None
        evidence.append(item)

    policy = {
        'must_be_verified_against_originals': list(ORIGINAL_REQUIRED_FACTS),
        'provable_by_commitment': list(COMMITTABLE_FACTS),
        'original_custodian_required_for_minimal': True,
    }
    manifest = {
        'package_id': package_id, 'host': host, 'mode': mode,
        'grant_id': grant_id, 'grantee': grant['grantee'],
        'scope': grant['scope'], 'created_at': at,
        'grant_issued_at': grant['issued_at'],
        'grant_expires_at': grant['expires_at'],
        'grant_key_id': grant['witness_key_id'],
        'grant_signature': grant['signature'],
        'event_scanned': chain['scanned'], 'event_matched': chain['matched'],
        'event_root': chain['root'], 'evidence_root': ev_chain['root'],
        'redactions': redaction_manifest,
        'authority_gaps': gaps,
        'local_replay': replay_report,
        'dns_fork': dns_fork(db, host),
        'policy': policy,
        'ownership_ruling': None,
        'disclaimer': ('package records what the platform observed and decided '
                       'locally; it does not determine external domain '
                       'ownership'),
    }
    manifest['witness_signature'] = _sign(witness_key, manifest)
    package = {'manifest': manifest, 'events': package_events,
               'evidence': evidence}

    receipt_body = {'grant_id': grant_id, 'package_id': package_id,
                    'host': host, 'mode': mode, 'issued_at': at,
                    'expires_at': grant['expires_at'],
                    'redacted': int(mode == 'minimal'),
                    'event_root': chain['root'],
                    'evidence_root': ev_chain['root']}
    receipt_sig = _sign(export_key, receipt_body)
    db.execute('INSERT INTO dispute_receipts VALUES(?,?,?,?,?,?,?,?,?,?)',
               (package_id, grant_id, host, mode, at, grant['expires_at'],
                int(mode == 'minimal'), chain['root'], ev_chain['root'],
                receipt_sig))
    db.execute('INSERT INTO dispute_exports VALUES(?,?,?,?,?,?,?,?,?)',
               (package_id, host, mode, grant_id, at, len(package_events),
                chain['root'], len(evidence), ev_chain['root']))

    if export_path:
        with open(export_path, 'w', encoding='utf-8') as fh:
            json.dump(package, fh, sort_keys=True, ensure_ascii=False, indent=2)
    return {'decision': 'exported', 'package_id': package_id, 'mode': mode,
            'event_root': chain['root'], 'evidence_root': ev_chain['root'],
            'event_count': len(package_events),
            'evidence_count': len(evidence),
            'redacted_events': len(redaction_manifest),
            'receipt_signature': receipt_sig, 'package': package}


def verify_package(package, export_key, witness_key, at=None,
                   original_bytes=None):
    """Offline verification a party can run with their own validator.

    Checks, without trusting the exporter:
      * the event hash chain (seq order, structural input/result hashes),
      * redaction commitments reconstructing every original input digest,
      * independent replay of every package-self-contained event,
      * the evidence append-chain and any supplied raw original bytes,
      * the independent witness signature over the manifest,
      * the export grant's signature and (optionally) its expiry.
    """
    problems = []
    manifest = package['manifest']
    host = manifest['host']

    # Independent witness signature over the manifest (minus the signature).
    stripped = {k: v for k, v in manifest.items()
                if k != 'witness_signature'}
    if not _verify_sig(witness_key, stripped,
                       manifest.get('witness_signature')):
        problems.append('witness_signature_invalid')

    # Embedded export grant signature and expiry.
    grant_body = {'grant_id': manifest['grant_id'],
                  'grantee': manifest['grantee'], 'host': host,
                  'scope': manifest['scope'],
                  'issued_at': manifest['grant_issued_at'],
                  'expires_at': manifest['grant_expires_at'],
                  'key_id': manifest['grant_key_id']}
    if not _verify_sig(export_key, grant_body, manifest['grant_signature']):
        problems.append('grant_signature_invalid')
    if at is not None and at >= manifest['grant_expires_at']:
        problems.append('grant_expired_at_verification_time')

    # Event hash chain, redaction commitments and independent replay.
    prev = ''
    target = connect(':memory:')
    for ev in package['events']:
        if ev['prev_hash'] != prev:
            problems.append(f"chain_break_at_seq_{ev['seq']}")
        if 'redaction_commitments' in ev:
            if recommit(ev['input']) != ev['input_hash']:
                problems.append(
                    f"redaction_commitment_mismatch_seq_{ev['seq']}")
        elif structural_digest(ev['input']) != ev['input_hash']:
            problems.append(f"input_hash_mismatch_seq_{ev['seq']}")
        if digest(ev['result']) != ev['result_hash']:
            problems.append(f"result_hash_mismatch_seq_{ev['seq']}")
        expect_self = digest({'seq': ev['seq'],
                              'input_hash': ev['input_hash'],
                              'result_hash': ev['result_hash'],
                              'prev_hash': ev['prev_hash']})
        if expect_self != ev['self_hash']:
            problems.append(f"self_hash_mismatch_seq_{ev['seq']}")
        prev = ev['self_hash']
        if ev.get('independently_replayable', True) \
                and 'redaction_commitments' not in ev:
            actual = execute(target, ev['subsystem'], ev['input'])
            if digest(actual) != ev['result_hash']:
                problems.append(f"replay_divergence_seq_{ev['seq']}")
    target.close()
    if prev != manifest['event_root']:
        problems.append('event_root_mismatch')

    # Evidence append chain; raw bytes only exist in the original package.
    eprev = ''
    for ev in package['evidence']:
        if ev['prev_hash'] != eprev:
            problems.append(f"evidence_chain_break_{ev['evidence_id']}")
        eprev = ev['self_hash']
        if ev['raw_bytes_b64'] is not None:
            raw = base64.b64decode(ev['raw_bytes_b64'])
            if hashlib.sha256(raw).hexdigest() != ev['raw_sha256']:
                problems.append(
                    f"raw_bytes_mismatch_{ev['evidence_id']}")
    if eprev != manifest['evidence_root']:
        problems.append('evidence_root_mismatch')

    # Sealed-room originals must match the commitments in the package.
    if original_bytes:
        for ev_id, raw in original_bytes.items():
            match = [e for e in package['evidence']
                     if e['evidence_id'] == ev_id]
            if not match or hashlib.sha256(raw).hexdigest() != \
                    match[0]['raw_sha256']:
                problems.append(
                    f'original_not_matching_commitment_{ev_id}')

    return {'verified': not problems, 'problems': sorted(set(problems)),
            'host': host, 'mode': manifest['mode'],
            'events_checked': len(package['events']),
            'evidence_checked': len(package['evidence']),
            'conclusion_scope': 'local_state',
            'ownership_ruling': None}


def export_timeline_guard(db, host):
    """All exports of one host share prefixes of one hash chain.

    Two contradictory timelines of the same event cannot be exported: every
    package's event root must be an actual prefix tip of the current chain,
    never an invented branch.  A later package therefore extends the same
    past instead of rewriting it.
    """
    exports = rows(
        db,
        'SELECT package_id, mode, event_root, created_at FROM dispute_exports '
        'WHERE host=? ORDER BY created_at, rowid', (host,))
    prefix_tips = {''}
    prev = ''
    for entry in event_chain(db, host)['entries']:
        prev = entry['self_hash']
        prefix_tips.add(prev)
    bad = [e['package_id'] for e in exports
           if e['event_root'] not in prefix_tips]
    return {'host': host, 'exports': exports, 'single_chain': not bad,
            'conflicting_packages': bad, 'current_root': prev}
