import ast
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from edgehandoff.store import connect
from edgehandoff.zone_bundle import add_record, draft
from edgehandoff import portable_zone as pz
from edgehandoff.portable_zone import (
    HardwareBackedKey, SigningKey, TargetPlatform, assess_recursive_trust,
    accept_formal_zone, acknowledge_customer, build_package, canonical,
    classify_record, elect_rule_resolution, equivalence_probe,
    ingest_zone_records, issue_target_formal, review_import,
    store_weighted_rule, verify_acknowledgment, verify_content,
    LEGACY_SNAPSHOT, TARGET_FORMAL, INTERNAL_SCOPE)

HOST = 'shop.example'
PROFILE = dict(pz.TARGET_DEFAULT_PROFILE)


def zone_rows():
    # Public business records, one platform-internal health name, plus a
    # weighted geo rule whose answers differ by customer region.
    return [
        {'label': 'api', 'kind': 'A', 'value': '192.0.2.10', 'ttl': 300},
        {'label': 'api', 'kind': 'AAAA', 'value': '2001:db8::10', 'ttl': 300},
        {'label': 'www', 'kind': 'CNAME', 'value': 'api.shop.example', 'ttl': 300},
        {'label': 'mx1', 'kind': 'MX', 'value': '10 mail.shop.example', 'ttl': 600},
        {'label': '_health', 'kind': 'A', 'value': '10.10.9.9', 'ttl': 30},
    ]


def rule_rows():
    # The shared primary is legal in every region; regional weighting differs
    # via region-specific secondary targets, which the target platform cannot
    # reproduce without the weighted engine.
    return [
        ('geo-1', 'cn-north', '192.0.2.20', 70),
        ('geo-1', 'cn-north', '192.0.2.21', 30),
        ('geo-1', 'cn-south', '192.0.2.20', 80),
        ('geo-1', 'cn-south', '192.0.2.30', 20),
        ('geo-1', 'eu-west', '192.0.2.20', 60),
        ('geo-1', 'eu-west', '198.51.100.40', 40),
    ]


class PortableZoneTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = connect(':memory:')
        self.db.execute("INSERT INTO claims VALUES('shop.example','cust-7',3,9999,'challenge-x','verified')")
        self.db.execute("INSERT INTO claims VALUES('other.example','cust-9',1,9999,'ch','verified')")
        ingest_zone_records(self.db, HOST, zone_rows())
        for rule_id, region, target, weight in rule_rows():
            store_weighted_rule(self.db, rule_id, HOST, 'edge', region, target, weight)
        # Another tenant's record must never enter this customer's package.
        ingest_zone_records(self.db, 'other.example',
                            [{'label': 'api', 'kind': 'A', 'value': '203.0.113.7'}])
        self.hsm = HardwareBackedKey('legacy-hsm-1', 'hsm-secret', role=LEGACY_SNAPSHOT)
        self.target_key = SigningKey('target-ksk-1', 'target-secret', role=TARGET_FORMAL)
        self.customer_key = SigningKey('cust-7-key', 'customer-secret', role='customer')
        self.keyring = {self.hsm.key_id: self.hsm, self.target_key.key_id: self.target_key,
                        self.customer_key.key_id: self.customer_key}

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def snapshot(self, package_id='pkg-snap', signed_at=100, expires_at=200):
        out = build_package(self.db, package_id, HOST, self.hsm, LEGACY_SNAPSHOT,
                            signed_at, expires_at, target_profile=PROFILE)
        self.assertEqual(out['decision'], 'drafted')
        return out['package'], out['content_hash']

    def formal(self, package_id='pkg-formal', signed_at=150, expires_at=900):
        out = build_package(self.db, package_id, HOST, self.target_key, TARGET_FORMAL,
                            signed_at, expires_at, target_profile=PROFILE)
        self.assertEqual(out['decision'], 'drafted')
        return out['package'], out['content_hash']

    # 1. Internal name isolation ------------------------------------------------
    def test_internal_health_name_is_excluded_but_completeness_is_checkable(self):
        self.assertEqual(classify_record('_health'), INTERNAL_SCOPE)
        pkg, digest = self.snapshot()
        manifest = pkg['content']['manifest']
        labels = [r['label'] for r in pkg['content']['records']]
        self.assertNotIn('_health', labels)
        self.assertEqual(manifest['record_count_included'], 4)
        self.assertEqual(manifest['record_count_excluded'], 1)
        # The internal name and its address must not appear anywhere in the
        # serialized customer deliverable.
        blob = canonical(pkg).decode()
        self.assertNotIn('_health', blob)
        self.assertNotIn('10.10.9.9', blob)
        # Exclusion is still provable: opaque id + completeness root reconcile.
        structural = verify_content(pkg)
        self.assertTrue(structural['ok'])
        names = [c['check'] for c in structural['checks']]
        self.assertIn('completeness_root', names)
        self.assertIn('source_total_arithmetically_consistent', names)
        ledger = pkg['content']['exclusion_ledger']
        self.assertEqual(ledger[0]['scope'], INTERNAL_SCOPE)
        self.assertNotIn('label', ledger[0])
        # Other tenants' records are absent too.
        self.assertNotIn('203.0.113.7', blob)

    def test_tampered_completeness_root_is_rejected(self):
        pkg, _ = self.snapshot()
        pkg['content']['manifest']['completeness_root'] = 'deadbeef'
        review = review_import(pkg, self.keyring, target_profile=PROFILE, at=120)
        self.assertEqual(review['decision'], 'rejected')
        self.assertEqual(review['reason'], 'content_verification_failed')

    # 2. Weighted rule difference ------------------------------------------------
    def test_weighted_rule_blocks_import_until_customer_makes_explicit_choice(self):
        pkg, _ = self.snapshot()
        review = review_import(pkg, self.keyring, target_profile=PROFILE, at=120)
        self.assertEqual(review['decision'], 'blocked_pending_customer_election')
        rule = review['weighted_rule_results'][0]
        self.assertTrue(rule['requires_explicit_choice'])
        self.assertEqual(rule['import_decision'], 'blocked_pending_customer_election')
        # Each rule carries original rule, semantics and the target's verdict.
        self.assertEqual(rule['resolution_semantics']['expected_answers']['cn-south'],
                         ['192.0.2.20', '192.0.2.30'])
        self.assertFalse(rule['target_import']['supported'])

    def test_equivalence_probe_detects_different_answers_by_region(self):
        pkg, _ = self.snapshot()
        # Without an election, the target simply has no answer for edge: counts
        # alone would hide this; the probe compares actual resolution sets.
        target = TargetPlatform(PROFILE)
        target.load(pkg, {})
        probe = equivalence_probe(pkg, target, {})
        self.assertFalse(probe['all_equivalent'])
        rule_finding = next(f for f in probe['findings'] if f['kind'] == 'weighted_rule')
        self.assertEqual(rule_finding['reason'], 'no_customer_election')

    def test_signed_election_unblocks_and_pin_choice_is_probed(self):
        pkg, digest = self.snapshot()
        bad = elect_rule_resolution(pkg, 'geo-1', 'not-an-option', self.customer_key, 130)
        self.assertEqual(bad['decision'], 'invalid_option')
        election = elect_rule_resolution(pkg, 'geo-1', 'pin_primary', self.customer_key, 130)
        self.assertEqual(election['decision'], 'elected')
        elected_pkg = election['package']
        # Election is an amendment: fixed content hash is untouched.
        self.assertEqual(pz.content_hash(elected_pkg), digest)
        review = review_import(elected_pkg, self.keyring, target_profile=PROFILE, at=140)
        self.assertEqual(review['decision'], 'sandbox_accepted_recursive_pending')
        # The pinned answer is one of the region's legitimate original targets.
        rule_finding = next(f for f in review['equivalence_probe']['findings']
                            if f['kind'] == 'weighted_rule')
        self.assertTrue(rule_finding['equivalent'])
        self.assertIn(rule_finding['actual_by_region']['cn-north'][0],
                      rule_finding['expected_by_region']['cn-north'])

    def test_forged_election_amendment_is_rejected(self):
        pkg, _ = self.snapshot()
        election = elect_rule_resolution(pkg, 'geo-1', 'pin_primary', self.customer_key, 130)
        elected = election['package']
        elected['amendments'][0]['option_id'] = 'split_labels'
        review = review_import(elected, self.keyring, target_profile=PROFILE, at=140)
        self.assertEqual(review['decision'], 'rejected')
        self.assertEqual(review['reason'], 'unsigned_election_amendment')

    def test_amendment_anchor_must_be_a_real_signed_envelope(self):
        pkg, _ = self.snapshot()
        election = elect_rule_resolution(pkg, 'geo-1', 'pin_primary', self.customer_key, 130)
        elected = election['package']
        # Re-point the amendment at an invented hash with no envelope behind it;
        # even a correctly-signed amendment must not be accepted on that anchor.
        elected['amendments'][0]['base_content_hash'] = 'f' * 64
        body = canonical({k: v for k, v in elected['amendments'][0].items() if k != 'signature'})
        elected['amendments'][0]['signature'] = self.customer_key.sign(body)
        review = review_import(elected, self.keyring, target_profile=PROFILE, at=140)
        self.assertEqual(review['decision'], 'rejected')
        self.assertEqual(review['reason'], 'unsigned_election_amendment')

    def test_split_labels_election_publishes_region_correct_static_names(self):
        pkg, _ = self.snapshot()
        election = elect_rule_resolution(pkg, 'geo-1', 'split_labels', self.customer_key, 130)
        review = review_import(election['package'], self.keyring, target_profile=PROFILE, at=140)
        self.assertEqual(review['decision'], 'sandbox_accepted_recursive_pending')
        rule_finding = next(f for f in review['equivalence_probe']['findings']
                            if f['kind'] == 'weighted_rule')
        self.assertTrue(rule_finding['equivalent'])
        # The region-specific static names now exist on the target platform.
        target = review['load_report']
        self.assertIn({'rule_id': 'geo-1', 'loaded': True, 'option': 'split_labels'}, target)

    def test_retain_external_election_makes_no_target_routing_claim(self):
        pkg, _ = self.snapshot()
        election = elect_rule_resolution(pkg, 'geo-1', 'retain_external', self.customer_key, 130)
        review = review_import(election['package'], self.keyring, target_profile=PROFILE, at=140)
        self.assertEqual(review['decision'], 'sandbox_accepted_recursive_pending')
        rule_result = review['weighted_rule_results'][0]
        self.assertEqual(rule_result['import_decision'], 'accepted:retain_external')

    # 3. Old key non-exportable --------------------------------------------------
    def test_legacy_private_key_cannot_be_exported(self):
        with self.assertRaises(pz.KeyNotExportable):
            self.hsm.export_private()
        # The target key is ordinary software material and can be generated/exported.
        self.assertEqual(self.target_key.export_private(), b'target-secret')

    def test_snapshot_must_be_signed_by_legacy_role_and_target_key_is_refused(self):
        out = build_package(self.db, 'pkg-wrong-role', HOST, self.target_key,
                            LEGACY_SNAPSHOT, 100, 200, target_profile=PROFILE)
        self.assertEqual(out['decision'], 'signer_role_mismatch')

    def test_validator_distinguishes_legacy_snapshot_from_target_formal_signature(self):
        snap, _ = self.snapshot()
        formal, _ = self.formal()
        snap_roles = verify_content(snap) and {e['role'] for e in snap['signatures']}
        formal_roles = {e['role'] for e in formal['signatures']}
        self.assertEqual(snap_roles, {LEGACY_SNAPSHOT})
        self.assertEqual(formal_roles, {TARGET_FORMAL})
        # A snapshot envelope cannot authenticate a formal contract package.
        review = review_import(formal, {self.hsm.key_id: self.hsm,
                                        self.customer_key.key_id: self.customer_key},
                               target_profile=PROFILE, at=160)
        self.assertEqual(review['decision'], 'rejected')
        self.assertEqual(review['reason'], 'unknown_signer')

    # 4. Parent DS late ----------------------------------------------------------
    def test_target_formal_zone_loads_but_recursive_trust_waits_for_parent_ds(self):
        formal, _ = self.formal()
        election = elect_rule_resolution(formal, 'geo-1', 'pin_primary', self.customer_key, 160)
        formal_elected = election['package']
        # Records load and offline import review passes.
        review = review_import(formal_elected, self.keyring, target_profile=PROFILE, at=170)
        self.assertEqual(review['decision'], 'importable_pending_ds')
        # Parent still publishes only the legacy HSM digest: target signature
        # validates locally but no recursive resolver will trust it yet.
        parent_ds = [self.hsm.ds_digest]
        trust = assess_recursive_trust(formal_elected, self.keyring, parent_ds, {}, at=170)
        self.assertEqual(trust['decision'], 'recursive_pending_ds')
        self.assertEqual(trust['expected_ds_digest'], self.target_key.ds_digest)
        blocked = accept_formal_zone(formal_elected, self.keyring, parent_ds, {}, at=170)
        self.assertEqual(blocked['decision'], 'formal_acceptance_pending')
        # Once the parent DS receipt arrives, formal acceptance completes.
        trust2 = assess_recursive_trust(formal_elected, self.keyring,
                                        [self.target_key.ds_digest], {}, at=180)
        self.assertEqual(trust2['decision'], 'recursive_trusted')
        accepted = accept_formal_zone(formal_elected, self.keyring,
                                      [self.target_key.ds_digest], {}, at=180)
        self.assertEqual(accepted['decision'], 'formally_accepted')

    def test_stale_resolver_cache_ttl_keeps_zone_untrusted_even_after_ds_switch(self):
        formal, _ = self.formal()
        cache = {'edge.shop.example': {'ds_digest': self.hsm.ds_digest, 'valid_until': 250}}
        trust = assess_recursive_trust(formal, self.keyring, [self.target_key.ds_digest],
                                       cache, at=200)
        self.assertEqual(trust['decision'], 'recursive_pending_cache_ttl')
        # After the cached TTL expires the same inputs become trustworthy.
        trust2 = assess_recursive_trust(formal, self.keyring, [self.target_key.ds_digest],
                                        cache, at=251)
        self.assertEqual(trust2['decision'], 'recursive_trusted')

    # 5. Short-lived snapshot expiry ---------------------------------------------
    def test_legacy_snapshot_expires_and_needs_renewal(self):
        snap, _ = self.snapshot(signed_at=100, expires_at=200)
        ok = review_import(snap, self.keyring, target_profile=PROFILE, at=150)
        self.assertIn(ok['decision'], ('blocked_pending_customer_election',
                                       'sandbox_accepted_recursive_pending'))
        expired = review_import(snap, self.keyring, target_profile=PROFILE, at=201)
        self.assertEqual(expired['decision'], 'rejected')
        self.assertEqual(expired['reason'], 'signature_expired')
        trust = assess_recursive_trust(snap, self.keyring, [self.hsm.ds_digest], {}, at=201)
        self.assertEqual(trust['decision'], 'untrusted')
        self.assertEqual(trust['reason'], 'signature_expired')
        # Even with the parent DS still on the old key, the snapshot is
        # sandbox-only and can never be declared the formal recursive zone.
        trust_live = assess_recursive_trust(snap, self.keyring, [self.hsm.ds_digest], {}, at=150)
        self.assertEqual(trust_live['decision'], 'sandbox_only')

    def test_contract_a_two_stage_handoff_snapshot_then_target_resign(self):
        # Stage 1: outgoing operator's HSM co-signs the fixed-content snapshot.
        snap, digest = self.snapshot()
        election = elect_rule_resolution(snap, 'geo-1', 'pin_primary', self.customer_key, 130)
        snap_elected = election['package']
        stage1 = review_import(snap_elected, self.keyring, target_profile=PROFILE, at=140)
        self.assertEqual(stage1['decision'], 'sandbox_accepted_recursive_pending')
        # Stage 2: target re-signs the same fixed zone content with its new key.
        resigned = issue_target_formal(snap_elected, self.target_key, 150, 900)
        self.assertEqual(resigned['decision'], 'target_signed')
        formal_pkg = resigned['package']
        # The zone data itself is byte-identical; only the contract role and
        # signature envelope change during promotion.
        self.assertEqual(canonical(formal_pkg['content']['records']),
                         canonical(snap_elected['content']['records']))
        self.assertEqual(canonical(formal_pkg['content']['weighted_rules']),
                         canonical(snap_elected['content']['weighted_rules']))
        self.assertNotEqual(pz.content_hash(formal_pkg), digest)
        # The customer's election still pins the original snapshot content.
        self.assertEqual(formal_pkg['amendments'][0]['base_content_hash'], digest)
        # Formal envelope is present; legacy envelope retained as audit anchor.
        self.assertEqual({e['role'] for e in formal_pkg['signatures']},
                         {TARGET_FORMAL, LEGACY_SNAPSHOT})
        # DS receipt late: still pending; after receipt: formally accepted.
        self.assertEqual(
            assess_recursive_trust(formal_pkg, self.keyring, [self.hsm.ds_digest], {}, 160)['decision'],
            'recursive_pending_ds')
        accepted = accept_formal_zone(formal_pkg, self.keyring, [self.target_key.ds_digest], {}, 160)
        self.assertEqual(accepted['decision'], 'formally_accepted')

    # 6. Customer later changes records ------------------------------------------
    def test_acknowledged_version_cannot_be_silently_replaced(self):
        pkg, digest = self.snapshot('pkg-pin')
        receipt = acknowledge_customer(pkg, digest, self.customer_key, 140)
        self.assertEqual(receipt['decision'], 'acknowledged')
        self.assertTrue(verify_acknowledgment(pkg, receipt['receipt'], self.customer_key)['ok'])
        # A new source record appears after the customer signed for the version.
        ingest_zone_records(self.db, HOST,
                            [{'label': 'new-api', 'kind': 'A', 'value': '192.0.2.77'}])
        again = build_package(self.db, 'pkg-pin', HOST, self.hsm, LEGACY_SNAPSHOT,
                              100, 200, target_profile=PROFILE)
        self.assertEqual(again['decision'], 'content_changed_after_seal')
        # Tampering with the sealed package content invalidates the receipt too.
        tampered = json.loads(json.dumps(pkg))
        tampered['content']['records'][0]['original_value'] = '192.0.2.250'
        self.assertFalse(verify_acknowledgment(tampered, receipt['receipt'], self.customer_key)['ok'])

    def test_rebuild_with_unchanged_content_reuses_sealed_artifact(self):
        pkg1, d1 = self.snapshot('pkg-idempotent')
        again = build_package(self.db, 'pkg-idempotent', HOST, self.hsm, LEGACY_SNAPSHOT,
                              100, 200, target_profile=PROFILE)
        self.assertEqual(again['decision'], 'reused')
        self.assertEqual(again['content_hash'], d1)

    # 7. Reproducible conclusion without the source database ---------------------
    def test_validator_conclusion_reproduces_from_package_file_only(self):
        pkg, digest = self.snapshot('pkg-offline')
        election = elect_rule_resolution(pkg, 'geo-1', 'pin_primary', self.customer_key, 130)
        pkg = election['package']
        path = Path(self.tmp.name) / 'package.json'
        path.write_bytes(canonical(pkg))
        self.db.close()
        # Fresh process: only the package file and public key material are given.
        repo = Path(__file__).resolve().parents[1]
        script = (
            'import json,sys\n'
            f'sys.path.insert(0,{str(repo)!r})\n'
            'from edgehandoff.portable_zone import review_import, SigningKey, LEGACY_SNAPSHOT\n'
            'pkg=json.load(open(sys.argv[1]))\n'
            'keyring={"legacy-hsm-1":SigningKey("legacy-hsm-1","hsm-secret",role=LEGACY_SNAPSHOT),'
            '"cust-7-key":SigningKey("cust-7-key","customer-secret",role="customer")}\n'
            'r=review_import(pkg,keyring,at=140)\n'
            'print(r["decision"])\n'
            'print(sorted(r["record_results"][0]["permission_source"]))\n')
        proc = subprocess.run([sys.executable, '-I', '-c', script, str(path)],
                              cwd=repo, capture_output=True, text=True, check=True)
        lines = proc.stdout.strip().splitlines()
        self.assertEqual(lines[0], 'sandbox_accepted_recursive_pending')
        self.assertEqual(ast.literal_eval(lines[1]),
                         sorted(['host', 'claim_holder', 'claim_epoch', 'claim_status']))
        # Re-running yields the identical, deterministic conclusion.
        proc2 = subprocess.run([sys.executable, '-I', '-c', script, str(path)],
                               cwd=Path(__file__).resolve().parents[1],
                               capture_output=True, text=True, check=True)
        self.assertEqual(proc.stdout, proc2.stdout)

    # Claim gating and the documented naive trap --------------------------------
    def test_unverified_claim_cannot_produce_package(self):
        self.db.execute("UPDATE claims SET status='pending' WHERE host='shop.example'")
        out = build_package(self.db, 'pkg-no-claim', HOST, self.hsm, LEGACY_SNAPSHOT,
                            100, 200, target_profile=PROFILE)
        self.assertEqual(out['decision'], 'claim_not_verified')

    def test_naive_draft_still_leaks_and_loses_semantics(self):
        # Documents the failure mode of the existing entry point: a count and a
        # raw JSON export cannot carry isolation, semantics or signatures.
        add_record(self.db, HOST, '_health', 'A', '10.10.9.9')
        add_record(self.db, HOST, 'api', 'A', '192.0.2.10')
        naive = draft(self.db, 'naive-1', HOST)
        self.assertEqual(naive['record_count'], 2)
        exported = [dict(r) for r in self.db.execute(
            'SELECT label,kind,value FROM zone_records WHERE host=? ORDER BY label', (HOST,))]
        self.assertIn({'label': '_health', 'kind': 'A', 'value': '10.10.9.9'}, exported)
        # And under the still-old parent DS, a target-new signature fails trust.
        formal, _ = self.formal()
        trust = assess_recursive_trust(formal, self.keyring, [self.hsm.ds_digest], {}, at=170)
        self.assertEqual(trust['decision'], 'recursive_pending_ds')

    def test_every_record_carries_permission_original_semantics_and_import_result(self):
        pkg, _ = self.snapshot()
        review = review_import(pkg, self.keyring, target_profile=PROFILE, at=120)
        for rec in review['record_results']:
            self.assertEqual(rec['permission_source']['claim_status'], 'verified')
            self.assertEqual(rec['permission_source']['host'], HOST)
            self.assertIn('original_value', rec)
            self.assertEqual(rec['resolution_semantics']['type'], 'simple_record')
            self.assertIn('supported', rec['target_import'])

    def test_unsupported_record_kind_is_marked_not_silently_dropped(self):
        profile = {'name': 'narrow-target', 'supported_kinds': ['A'], 'weighted_routing': False}
        out = build_package(self.db, 'pkg-narrow', HOST, self.hsm, LEGACY_SNAPSHOT,
                            100, 200, target_profile=profile)
        pkg = out['package']
        kinds = {r['kind']: r['target_import'] for r in pkg['content']['records']}
        self.assertFalse(kinds['MX']['supported'])
        self.assertIsNone(kinds['MX']['imported_as'])
        self.assertTrue(kinds['A']['supported'])


if __name__ == '__main__':
    unittest.main()
