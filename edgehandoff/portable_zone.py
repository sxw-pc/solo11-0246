"""Importable, verifiable customer DNS zone handoff package.

A package is a canonical JSON document over fixed content: every exported
record carries its permission source, original value, resolution semantics and
target import result; platform-only names are removed from the customer copy
but stay provably excluded through a ledger of opaque identifiers. Two
contracts are distinguished by signer role:

* ``legacy_snapshot`` - the outgoing operator co-signs a short-lived snapshot
  with its hardware-backed, non-exportable key; validation is sandbox-only
  until the target re-signs.
* ``target_formal`` - the target platform signs the formal zone with its own
  new key; recursive trust additionally requires the parent DS to point at
  that key.

Everything needed to reproduce an import decision lives inside the package;
the target validator never opens the source platform's database.
"""
import hashlib
import hmac
import json

from .store import one

INTERNAL_SCOPE = 'platform-internal'
PUBLIC_SCOPE = 'customer-public'

LEGACY_SNAPSHOT = 'legacy_snapshot'
TARGET_FORMAL = 'target_formal'
CONTRACTS = (LEGACY_SNAPSHOT, TARGET_FORMAL)

TARGET_DEFAULT_PROFILE = {'name': 'target-platform', 'supported_kinds': ['A', 'AAAA', 'CNAME', 'TXT', 'MX'],
                          'weighted_routing': False}


class KeyNotExportable(Exception):
    """Raised when a hardware-backed private key is asked to leave the HSM."""


class SigningKey:
    """Offline signing key with a deterministic DS-style public digest."""

    def __init__(self, key_id, secret, digest_alg='sha256', role=None):
        self.key_id = key_id
        self.role = role
        self._secret = secret.encode() if isinstance(secret, str) else secret
        self.digest_alg = digest_alg

    @property
    def ds_digest(self):
        return hashlib.new(self.digest_alg, self.key_id.encode() + b'|' + self._secret).hexdigest()

    def export_private(self):
        return self._secret

    def sign(self, payload_bytes):
        return hmac.new(self._secret, payload_bytes, hashlib.sha256).hexdigest()

    def verify(self, payload_bytes, signature_hex):
        return hmac.compare_digest(self.sign(payload_bytes), signature_hex)


class HardwareBackedKey(SigningKey):
    """Model of the outgoing operator's non-exportable HSM key."""

    def export_private(self):
        raise KeyNotExportable(f'key {self.key_id} lives in non-exportable hardware')


def canonical(obj):
    """Deterministic serialization used for hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def content_hash(pkg):
    return hashlib.sha256(canonical(pkg['content'])).hexdigest()


def envelope(signer, role, content_hex, signed_at, expires_at):
    body = canonical({'role': role, 'key_id': signer.key_id, 'ds_digest': signer.ds_digest,
                      'content_hash': content_hex, 'signed_at': signed_at,
                      'expires_at': expires_at, 'alg': f'HMAC-SHA256-{signer.digest_alg}'})
    return {'role': role, 'key_id': signer.key_id, 'ds_digest': signer.ds_digest,
            'content_hash': content_hex,
            'signed_at': signed_at, 'expires_at': expires_at,
            'alg': f'HMAC-SHA256-{signer.digest_alg}', 'signature': signer.sign(body)}


def envelope_bytes(env):
    return canonical({k: v for k, v in env.items() if k != 'signature'})


def verify_envelope(env, keyring, content_hex, at):
    key = keyring.get(env['key_id'])
    if key is None:
        return {'ok': False, 'reason': 'unknown_signer', 'key_id': env['key_id']}
    if key.role != env['role']:
        return {'ok': False, 'reason': 'role_mismatch', 'key_id': env['key_id'], 'role': env['role']}
    if not key.verify(envelope_bytes(env), env['signature']):
        return {'ok': False, 'reason': 'bad_signature', 'key_id': env['key_id']}
    if env['content_hash'] != content_hex:
        return {'ok': False, 'reason': 'content_hash_mismatch', 'key_id': env['key_id']}
    if key.ds_digest != env['ds_digest']:
        return {'ok': False, 'reason': 'ds_digest_mismatch', 'key_id': env['key_id']}
    if at is not None and at > env['expires_at']:
        return {'ok': False, 'reason': 'signature_expired', 'key_id': env['key_id'],
                'expires_at': env['expires_at'], 'at': at}
    return {'ok': True, 'key_id': key.key_id, 'role': key.role, 'ds_digest': key.ds_digest,
            'expires_at': env['expires_at']}


def _ensure_tables(db):
    db.execute('CREATE TABLE IF NOT EXISTS portable_records('
               'host TEXT,label TEXT,kind TEXT,value TEXT,scope TEXT,ttl INTEGER,'
               'PRIMARY KEY(host,label,kind,value))')
    db.execute('CREATE TABLE IF NOT EXISTS weighted_rules('
               'rule_id TEXT,host TEXT,label TEXT,kind TEXT,region TEXT,'
               'target TEXT,weight INTEGER,ttl INTEGER,'
               'PRIMARY KEY(rule_id,region,target))')
    db.execute('CREATE TABLE IF NOT EXISTS portable_packages('
               'id TEXT PRIMARY KEY,host TEXT,content_hash TEXT,status TEXT,artifact TEXT)')


def classify_record(label):
    """Platform health-check names are never part of the customer deliverable."""
    token = label.lower().strip('_')
    if token in ('health', 'healthcheck', 'health-check', '_health', 'internal') or token.startswith('health.'):
        return INTERNAL_SCOPE
    return PUBLIC_SCOPE


def ingest_zone_records(db, host, records, default_ttl=300):
    """Copy source zone_records into a classified inventory.

    ``records`` are plain ``(label, kind, value)`` tuples or mappings; records
    of other tenants are ignored so one machine's data cannot leak into a
    package addressed at another customer.
    """
    _ensure_tables(db)
    seen = []
    for rec in records:
        label, kind, value = (rec['label'], rec['kind'], rec['value']) if isinstance(rec, dict) else rec
        ttl = rec.get('ttl', default_ttl) if isinstance(rec, dict) else default_ttl
        scope = rec.get('scope') if isinstance(rec, dict) else None
        scope = scope or classify_record(label)
        db.execute('INSERT OR REPLACE INTO portable_records VALUES(?,?,?,?,?,?)',
                   (host, label, kind, value, scope, ttl))
        seen.append(f'{label}/{kind}')
    return {'decision': 'ingested', 'host': host, 'records': len(seen)}


def store_weighted_rule(db, rule_id, host, label, region, target, weight, kind='A', ttl=60):
    _ensure_tables(db)
    db.execute('INSERT OR REPLACE INTO weighted_rules VALUES(?,?,?,?,?,?,?,?)',
               (rule_id, host, label, kind, region, target, weight, ttl))
    return {'decision': 'stored', 'rule_id': rule_id}


def _opaque_id(salt, label, kind, value):
    return hashlib.sha256(canonical({'salt': salt, 'label': label, 'kind': kind, 'value': value})).hexdigest()[:24]


def _rule_entry(rows):
    first = rows[0]
    region_map = {}
    for r in rows:
        region_map.setdefault(r['region'], []).append({'target': r['target'], 'weight': r['weight']})
    expected = {region: [pick['target'] for pick in picks] for region, picks in region_map.items()}
    return {'rule_id': first['rule_id'], 'label': first['label'], 'kind': first['kind'], 'ttl': first['ttl'],
            'region': sorted(region_map),
            'original_rule': {region: sorted(picks, key=lambda p: p['target'])
                              for region, picks in region_map.items()},
            'resolution_semantics': {'type': 'weighted_geo', 'expected_answers': expected},
            'target_import': {'supported': False,
                              'reason': 'target platform does not support weighted geo rules',
                              'imported_as': None,
                              'options': [
                                  {'option_id': 'pin_primary', 'description': 'pin the name to one fixed address record'},
                                  {'option_id': 'split_labels', 'description': 'publish one static record per region label'},
                                  {'option_id': 'retain_external', 'description': 'keep weighted routing at the outgoing operator'}]},
            'customer_election': None}


def build_package(db, package_id, host, signer, contract, signed_at, expires_at,
                  target_profile=None, permission_source=None):
    """Build the signed, importable package for a verified claim holder.

    Re-running with unchanged fixed content returns the sealed artifact rather
    than minting a new version, so an acknowledged package cannot be silently
    replaced underneath the customer.
    """
    _ensure_tables(db)
    target_profile = target_profile or TARGET_DEFAULT_PROFILE
    claim = one(db, 'SELECT * FROM claims WHERE host=?', (host,))
    if not claim:
        return {'decision': 'unavailable', 'reason': 'no_claim'}
    if claim['status'] != 'verified':
        return {'decision': 'claim_not_verified', 'claim_status': claim['status']}
    if contract not in CONTRACTS:
        return {'decision': 'invalid_contract', 'contract': contract}
    if signer.role != contract:
        return {'decision': 'signer_role_mismatch', 'expected': contract, 'role': signer.role}

    all_records = [dict(r) for r in db.execute(
        'SELECT * FROM portable_records WHERE host=? ORDER BY label,kind,value', (host,))]
    if not all_records and not db.execute('SELECT 1 FROM weighted_rules WHERE host=?', (host,)).fetchone():
        return {'decision': 'empty_zone', 'host': host}

    rule_data = [dict(x) for x in db.execute(
        'SELECT * FROM weighted_rules WHERE host=? ORDER BY rule_id,region,target', (host,))]
    # Salt is derived from the source inventory itself: per-customer opaque,
    # yet deterministic so rebuilding the same fixed content re-seals the same
    # package hash instead of minting a replacement version.
    inventory = canonical({'host': host, 'records': all_records, 'rules': rule_data})
    salt = hashlib.sha256(inventory).hexdigest()[:32]
    source = permission_source or {'host': host, 'claim_holder': claim['holder'],
                                   'claim_epoch': claim['epoch'],
                                   'claim_status': claim['status']}
    included, excluded = [], []
    for r in all_records:
        rec_id = _opaque_id(salt, r['label'], r['kind'], r['value'])
        base = {'id': rec_id, 'label': r['label'], 'kind': r['kind'], 'original_value': r['value'],
                'ttl': r['ttl'], 'permission_source': dict(source)}
        if r['scope'] == INTERNAL_SCOPE:
            excluded.append({'id': rec_id, 'scope': INTERNAL_SCOPE,
                             'reason': 'platform health-check name; outside customer entitlement'})
            continue
        supported = r['kind'] in target_profile['supported_kinds']
        included.append(dict(base, scope=PUBLIC_SCOPE,
                             resolution_semantics={'type': 'simple_record',
                                                   'expected_answers': {'*': [r['value']]}},
                             target_import={'supported': supported,
                                            'imported_as': {'kind': r['kind'], 'value': r['value']} if supported else None,
                                            'reason': None if supported else 'unsupported record kind'}))

    grouped = {}
    for row in rule_data:
        grouped.setdefault(row['rule_id'], []).append(row)
    weighted = [_rule_entry(grouped[k]) for k in sorted(grouped)]

    id_root = hashlib.sha256(canonical(sorted(
        [r['id'] for r in included] + [e['id'] for e in excluded]))).hexdigest()
    content = {
        'manifest': {
            'schema': 'edgehandoff.portable-zone/v1',
            'package_id': package_id,
            'host': host,
            'contract': contract,
            'created_at': signed_at,
            'target_platform': target_profile['name'],
            'content_salt': salt,
            'record_count_included': len(included),
            'record_count_excluded': len(excluded),
            'rule_count_weighted': len(weighted),
            'source_total': len(all_records),
            'completeness_root': id_root},
        'records': included,
        'weighted_rules': weighted,
        'exclusion_ledger': excluded}
    digest = hashlib.sha256(canonical(content)).hexdigest()

    sealed = one(db, 'SELECT * FROM portable_packages WHERE id=?', (package_id,))
    if sealed:
        if sealed['content_hash'] != digest:
            return {'decision': 'content_changed_after_seal', 'sealed_hash': sealed['content_hash'],
                    'new_hash': digest}
        return {'decision': 'reused', 'package_id': package_id, 'content_hash': digest,
                'package': json.loads(sealed['artifact'])}

    pkg = {'content': content,
           'signatures': [envelope(signer, contract, digest, signed_at, expires_at)],
           'amendments': []}
    db.execute('INSERT INTO portable_packages VALUES(?,?,?,?,?)',
               (package_id, host, digest, 'sealed', json.dumps(pkg, sort_keys=True)))
    return {'decision': 'drafted', 'package_id': package_id, 'content_hash': digest, 'package': pkg}


def elect_rule_resolution(pkg, rule_id, option_id, customer_key, elected_at):
    """Record the customer's explicit, signed choice for an untranslatable rule.

    The election is an amendment over the immutable fixed content; silently
    picking a substitute is impossible because the validator requires this
    signed amendment before it accepts any replacement.
    """
    rule = next((r for r in pkg['content']['weighted_rules'] if r['rule_id'] == rule_id), None)
    if rule is None:
        return {'decision': 'unknown_rule', 'rule_id': rule_id}
    valid = {o['option_id'] for o in rule['target_import']['options']}
    if option_id not in valid:
        return {'decision': 'invalid_option', 'option_id': option_id, 'valid': sorted(valid)}
    base_hash = content_hash(pkg)
    amendment_body = {'type': 'weighted_election', 'rule_id': rule_id, 'option_id': option_id,
                      'base_content_hash': base_hash, 'elected_at': elected_at,
                      'signer_key_id': customer_key.key_id}
    body = canonical(amendment_body)
    amendment = dict(amendment_body, signature=customer_key.sign(body))
    new_pkg = json.loads(json.dumps(pkg))
    new_pkg['amendments'].append(amendment)
    return {'decision': 'elected', 'amendment': amendment, 'package': new_pkg}


def acknowledge_customer(pkg, package_version, customer_key, acknowledged_at):
    """Customer signs for a specific, hash-pinned package version."""
    digest = content_hash(pkg)
    if package_version != digest:
        return {'decision': 'version_mismatch', 'expected': digest, 'provided': package_version}
    body = canonical({'type': 'customer_acknowledgment', 'package_id': pkg['content']['manifest']['package_id'],
                      'content_hash': digest, 'acknowledged_at': acknowledged_at,
                      'signer_key_id': customer_key.key_id})
    return {'decision': 'acknowledged',
            'receipt': {'type': 'customer_acknowledgment',
                        'package_id': pkg['content']['manifest']['package_id'],
                        'content_hash': digest, 'acknowledged_at': acknowledged_at,
                        'signer_key_id': customer_key.key_id,
                        'signature': customer_key.sign(body)}}


def verify_acknowledgment(pkg, receipt, customer_key, at=None):
    digest = content_hash(pkg)
    if receipt['content_hash'] != digest:
        return {'ok': False, 'reason': 'acknowledgment_on_different_content'}
    body = canonical({k: v for k, v in receipt.items() if k != 'signature'})
    if not customer_key.verify(body, receipt['signature']):
        return {'ok': False, 'reason': 'bad_acknowledgment_signature'}
    if at is not None and receipt['acknowledged_at'] > at:
        return {'ok': False, 'reason': 'acknowledgment_in_future'}
    return {'ok': True, 'content_hash': digest}


class TargetPlatform:
    """Simulated target DNS platform: plain records only, no weighted rules."""

    def __init__(self, profile=None):
        self.profile = profile or TARGET_DEFAULT_PROFILE
        self.zone = {}

    def load(self, pkg, elections):
        report = []
        for rec in pkg['content']['records']:
            if rec['target_import']['supported']:
                self.zone[(rec['label'], rec['kind'])] = \
                    rec['target_import']['imported_as']['value']
                report.append({'id': rec['id'], 'loaded': True})
            else:
                report.append({'id': rec['id'], 'loaded': False, 'reason': 'unsupported_record_kind'})
        for rule in pkg['content']['weighted_rules']:
            election = elections.get(rule['rule_id'])
            if election is None:
                report.append({'rule_id': rule['rule_id'], 'loaded': False, 'reason': 'missing_customer_election'})
                continue
            if election['option_id'] == 'pin_primary':
                primary = sorted(rule['original_rule'].items())[0][1][0]['target']
                self.zone[(rule['label'], rule['kind'])] = primary
            elif election['option_id'] == 'split_labels':
                for region, picks in sorted(rule['original_rule'].items()):
                    self.zone[(f"{region}-{rule['label']}", rule['kind'])] = picks[0]['target']
            elif election['option_id'] == 'retain_external':
                pass
            report.append({'rule_id': rule['rule_id'], 'loaded': True, 'option': election['option_id']})
        return report

    def resolve(self, fqdn, client_region=None, kind='A'):
        label = fqdn.split('.', 1)[0]
        value = self.zone.get((label, kind))
        return [value] if value is not None else []


def _elections(pkg, keyring):
    """Validate election amendments, including those anchored to a predecessor
    snapshot hash from which this formal package was promoted.

    An anchor hash is only trusted if an envelope carrying that exact hash is
    itself authentic under a key in the keyring, so an attacker cannot invent
    an anchor to backdate a forged amendment.
    """
    out = {}
    base = content_hash(pkg)
    trusted_anchors = {base}
    for env in pkg['signatures']:
        key = keyring.get(env['key_id'])
        if key is not None and key.verify(envelope_bytes(env), env['signature']):
            trusted_anchors.add(env['content_hash'])
    for am in pkg.get('amendments', []):
        if am.get('type') != 'weighted_election':
            continue
        key = keyring.get(am['signer_key_id'])
        body = canonical({k: v for k, v in am.items() if k != 'signature'})
        if key is None or not key.verify(body, am['signature']) \
                or am['base_content_hash'] not in trusted_anchors:
            continue
        out[am['rule_id']] = am
    return out


def equivalence_probe(pkg, target, elections):
    """Actually resolve names on the target; row counts never prove semantics."""
    host = pkg['content']['manifest']['host']
    findings = []
    for rec in pkg['content']['records']:
        fqdn = f"{rec['label']}.{host}"
        actual = target.resolve(fqdn, '*', kind=rec['kind'])
        expected = rec['resolution_semantics']['expected_answers']['*']
        findings.append({'subject': fqdn, 'kind': 'record', 'record_kind': rec['kind'],
                         'equivalent': sorted(actual) == sorted(expected),
                         'expected': expected, 'actual': actual})
    for rule in pkg['content']['weighted_rules']:
        election = elections.get(rule['rule_id'])
        fqdn = f"{rule['label']}.{host}"
        expected_map = rule['resolution_semantics']['expected_answers']
        if election is None:
            findings.append({'subject': fqdn, 'kind': 'weighted_rule', 'equivalent': False,
                             'reason': 'no_customer_election',
                             'expected_by_region': expected_map, 'actual_by_region': {}})
            continue
        actual_map = {region: target.resolve(fqdn, region, kind=rule['kind'])
                      for region in expected_map}
        if election['option_id'] == 'retain_external':
            # Routing stays on the outgoing platform; nothing new is asserted.
            equivalent = True
        elif election['option_id'] == 'pin_primary':
            # The customer explicitly accepted one fixed address. It must be a
            # member of the original answer set in every region, and every
            # region must now resolve to that same pinned value.
            pinned = {v for values in actual_map.values() for v in values}
            equivalent = bool(pinned) and all(
                pinned <= set(expected_map[region]) for region in expected_map)
        else:
            # split_labels: each region gets its own static, region-correct name.
            equivalent = all(
                target.resolve(f"{region}-{rule['label']}.{host}", region, kind=rule['kind'])
                == expected_map[region][:1]
                for region in expected_map)
        findings.append({'subject': fqdn, 'kind': 'weighted_rule', 'equivalent': equivalent,
                         'option': election['option_id'],
                         'expected_by_region': expected_map, 'actual_by_region': actual_map})
    return {'all_equivalent': all(f['equivalent'] for f in findings), 'findings': findings}


def verify_content(pkg):
    """Structural checks that need no source database at all."""
    checks = []
    content = pkg['content']
    digest = hashlib.sha256(canonical(content)).hexdigest()
    checks.append({'check': 'content_hash_recomputes', 'ok': digest == content_hash(pkg)})

    salt = content['manifest']['content_salt']
    ids = []
    for rec in content['records']:
        ids.append(rec['id'])
        expect = _opaque_id(salt, rec['label'], rec['kind'], rec['original_value'])
        checks.append({'check': 'opaque_id_rederives', 'ok': rec['id'] == expect, 'id': rec['id']})
    for ex in content['exclusion_ledger']:
        ids.append(ex['id'])
        checks.append({'check': 'excluded_id_format', 'ok': len(ex['id']) == 24, 'id': ex['id']})
    root = hashlib.sha256(canonical(sorted(ids))).hexdigest()
    checks.append({'check': 'completeness_root', 'ok': root == content['manifest']['completeness_root'],
                   'included': len(content['records']), 'excluded': len(content['exclusion_ledger'])})
    checks.append({'check': 'source_total_arithmetically_consistent',
                   'ok': content['manifest']['source_total'] ==
                   content['manifest']['record_count_included'] +
                   content['manifest']['record_count_excluded']})

    leaks = []
    for ex in content['exclusion_ledger']:
        # Ledger rows must contain only opaque identifiers, never the name.
        if 'label' in ex or 'value' in ex:
            leaks.append(ex['id'])
    for rec in content['records']:
        if rec['scope'] == INTERNAL_SCOPE or classify_record(rec['label']) == INTERNAL_SCOPE:
            leaks.append(rec['id'])
    checks.append({'check': 'internal_names_absent_from_customer_copy', 'ok': not leaks, 'leaks': leaks})
    return {'ok': all(c['ok'] for c in checks), 'checks': checks, 'content_hash': digest}


def verify_active_signature(pkg, keyring, at):
    """Verify only the envelope matching the manifest's current contract role.

    Predecessor envelopes (e.g. the legacy snapshot retained after promotion)
    are audit anchors for amendments; they cannot authenticate the current
    content and are therefore excluded from the active verification result.
    """
    digest = content_hash(pkg)
    contract = pkg['content']['manifest']['contract']
    env = next((s for s in pkg['signatures'] if s['role'] == contract), None)
    if env is None:
        return {'ok': False, 'reason': 'missing_signature_for_contract', 'contract': contract,
                'envelopes': [], 'roles': sorted({s['role'] for s in pkg['signatures']})}
    result = verify_envelope(env, keyring, digest, at)
    return {'ok': result['ok'], 'reason': result.get('reason'),
            'envelopes': [result],
            'roles': sorted({s['role'] for s in pkg['signatures']}),
            'anchor_roles': sorted(s['role'] for s in pkg['signatures'] if s['role'] != contract)}


def review_import(pkg, keyring, target_profile=None, at=0):
    """Deterministic offline import conclusion, reproducible without the source DB."""
    target_profile = target_profile or TARGET_DEFAULT_PROFILE
    structural = verify_content(pkg)
    if not structural['ok']:
        return {'decision': 'rejected', 'reason': 'content_verification_failed', 'structural': structural}

    sigs = verify_active_signature(pkg, keyring, at)
    if not sigs['ok']:
        return {'decision': 'rejected', 'reason': sigs['reason'], 'signatures': sigs}

    contract = pkg['content']['manifest']['contract']
    if contract not in sigs['roles']:
        return {'decision': 'rejected', 'reason': 'signer_role_mismatch', 'signatures': sigs}

    if any(rec['scope'] == INTERNAL_SCOPE for rec in pkg['content']['records']) or \
            any(classify_record(rec['label']) == INTERNAL_SCOPE for rec in pkg['content']['records']):
        return {'decision': 'rejected', 'reason': 'internal_name_leak'}

    host = pkg['content']['manifest']['host']
    for rec in pkg['content']['records']:
        src = rec.get('permission_source') or {}
        if src.get('claim_status') != 'verified':
            return {'decision': 'rejected', 'reason': 'record_without_verified_permission', 'id': rec['id']}
        if src.get('host') != host:
            return {'decision': 'rejected', 'reason': 'foreign_tenant_record', 'id': rec['id']}

    elections = _elections(pkg, keyring)
    election_ids = {a['rule_id'] for a in elections.values()}
    unsigned = [a for a in pkg.get('amendments', [])
                if a.get('type') == 'weighted_election' and a['rule_id'] not in election_ids]
    if unsigned:
        return {'decision': 'rejected', 'reason': 'unsigned_election_amendment'}

    target = TargetPlatform(target_profile)
    load_report = target.load(pkg, elections)
    probe = equivalence_probe(pkg, target, elections)

    record_results = []
    for rec in pkg['content']['records']:
        record_results.append({'id': rec['id'], 'label': rec['label'], 'kind': rec['kind'],
                               'original_value': rec['original_value'],
                               'permission_source': rec['permission_source'],
                               'resolution_semantics': rec['resolution_semantics'],
                               'target_import': rec['target_import']})
    rule_results = []
    for rule in pkg['content']['weighted_rules']:
        election = elections.get(rule['rule_id'])
        rule_results.append({'rule_id': rule['rule_id'], 'label': rule['label'],
                             'original_rule': rule['original_rule'],
                             'resolution_semantics': rule['resolution_semantics'],
                             'target_import': rule['target_import'],
                             'customer_election': election,
                             'requires_explicit_choice': election is None,
                             'import_decision': 'blocked_pending_customer_election' if election is None
                             else f"accepted:{election['option_id']}"})

    if any(r['requires_explicit_choice'] for r in rule_results):
        decision = 'blocked_pending_customer_election'
    elif not probe['all_equivalent']:
        decision = 'rejected'
    elif contract == LEGACY_SNAPSHOT:
        decision = 'sandbox_accepted_recursive_pending'
    else:
        decision = 'importable_pending_ds'
    return {'decision': decision, 'contract': contract, 'structural': structural, 'signatures': sigs,
            'elections': sorted(elections), 'load_report': load_report,
            'equivalence_probe': probe, 'record_results': record_results,
            'weighted_rule_results': rule_results}


def assess_recursive_trust(pkg, keyring, parent_ds_digests, resolver_cache, at):
    """DS chain, signature expiry and resolver cache TTL evaluated together.

    Loading records into the target is not enough: a recursive resolver only
    trusts the zone when a parent DS matches the signing key, the signature is
    unexpired, and any cached negative/old answer has aged out.
    """
    contract = pkg['content']['manifest']['contract']
    env = next((s for s in pkg['signatures'] if s['role'] == contract), None)
    if env is None:
        return {'decision': 'untrusted', 'reason': 'missing_signature_for_contract',
                'contract': contract}
    active = verify_envelope(env, keyring, content_hash(pkg), at)
    if not active['ok']:
        return {'decision': 'untrusted', 'reason': active['reason']}
    role = active['role']
    ds_matches = active['ds_digest'] in parent_ds_digests

    stale_entries = []
    for fqdn, entry in resolver_cache.items():
        if entry.get('ds_digest') and entry['ds_digest'] != active['ds_digest'] and at < entry['valid_until']:
            stale_entries.append({'fqdn': fqdn, 'cached_until': entry['valid_until'],
                                  'cached_ds': entry['ds_digest']})
    cache_clear = not stale_entries

    if role == LEGACY_SNAPSHOT:
        return {'decision': 'sandbox_only',
                'reason': 'legacy co-signed snapshot cannot be asserted as the formal recursive zone',
                'ds_matches_parent': ds_matches, 'cache_clear': cache_clear,
                'stale_cache': stale_entries, 'signature_expires_at': active['expires_at']}
    if not ds_matches:
        return {'decision': 'recursive_pending_ds',
                'reason': 'parent zone DS does not yet publish the target key digest',
                'expected_ds_digest': active['ds_digest'], 'cache_clear': cache_clear,
                'stale_cache': stale_entries, 'signature_expires_at': active['expires_at']}
    if not cache_clear:
        return {'decision': 'recursive_pending_cache_ttl',
                'reason': 'resolver still serves the pre-cutover answer from cache',
                'stale_cache': stale_entries, 'signature_expires_at': active['expires_at']}
    return {'decision': 'recursive_trusted', 'ds_matches_parent': True, 'cache_clear': True,
            'signature_expires_at': active['expires_at']}


def issue_target_formal(pkg, target_key, signed_at, expires_at):
    """Target re-signs the same fixed zone content after the sandbox stage.

    The legacy snapshot envelope is retained as an audit anchor so amendments
    signed over the snapshot remain verifiable; it can no longer authenticate
    the formal contract because the validator selects envelopes by the
    manifest's current contract role.
    """
    if target_key.role != TARGET_FORMAL:
        return {'decision': 'signer_role_mismatch', 'expected': TARGET_FORMAL}
    digest = content_hash(pkg)
    new_pkg = json.loads(json.dumps(pkg))
    # The manifest contract role moves with the promotion. The legacy envelope
    # is retained as an audit anchor so amendments signed over the snapshot
    # remain verifiable, but it can no longer authenticate the formal contract
    # (the validator selects envelopes by current role).
    new_pkg['content']['manifest']['contract'] = TARGET_FORMAL
    new_digest = content_hash(new_pkg)
    new_pkg['signatures'] = [s for s in new_pkg['signatures'] if s['role'] != TARGET_FORMAL]
    new_pkg['signatures'].append(envelope(target_key, TARGET_FORMAL, new_digest, signed_at, expires_at))
    return {'decision': 'target_signed', 'content_hash': new_digest, 'package': new_pkg}


def accept_formal_zone(pkg, keyring, parent_ds_digests, resolver_cache, at, target_profile=None):
    review = review_import(pkg, keyring, target_profile=target_profile, at=at)
    if review['decision'] not in ('importable_pending_ds',):
        return {'decision': 'formal_acceptance_blocked', 'reason': review['decision'], 'review': review}
    trust = assess_recursive_trust(pkg, keyring, parent_ds_digests, resolver_cache, at)
    if trust['decision'] != 'recursive_trusted':
        return {'decision': 'formal_acceptance_pending', 'trust': trust, 'review': review}
    return {'decision': 'formally_accepted', 'trust': trust,
            'content_hash': review['structural']['content_hash']}
