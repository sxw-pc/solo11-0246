import json
import tempfile
import unittest
from pathlib import Path

from edgehandoff.store import connect, execute, rows
from edgehandoff import dispute_archive as da

# The disputed host belongs locally to 甲 (team-a); other.example belongs to an
# unrelated customer whose private delegation must never leak into 甲's copy.
HOST = 'disputed.example'
OTHER = 'other-customer.example'
EXPORT_KEY = b'export-authority-secret'
WITNESS_KEY = b'independent-witness-secret'
DNS_SEAL = 'witness-dns-seal'
REGISTRAR_SEAL = 'witness-registrar-seal'


def build_disputed_db(path):
    """Recreate the 08:00-08:12 scenario described in the dispute brief."""
    db = connect(path)
    n = 0

    def step(sub, **fields):
        nonlocal n
        n += 1
        return execute(db, sub, dict(request_id=f'e-{n}', **fields))

    # 08:00 local ledger: 甲 holds the host, challenge C later proven locally.
    step('ownership', op='claim', host=HOST, holder='team-a', epoch=1,
         lease_until=1200, challenge='C', at=480)
    step('ownership', op='prove', host=HOST, epoch=1, challenge='C', at=480)
    # Private delegations: one for the disputed host, one for the unrelated
    # customer's host (its scope is private to that customer).
    step('ownership', op='delegate', id='del-a', host=HOST,
         grantor='team-a', grantee='team-b', scope='/svc', until_ts=900,
         at=481)
    step('ownership', op='claim', host=OTHER, holder='other-customer',
         epoch=1, lease_until=1200, challenge='OC', at=482)
    step('ownership', op='prove', host=OTHER, epoch=1, challenge='OC',
         at=483)
    step('ownership', op='delegate', id='del-other', host=OTHER,
         grantor='other-customer', grantee='team-b', scope='/',
         until_ts=900, at=484)
    # 08:07 platform accepts 甲's service delegation via a cross-domain
    # certificate order that also names the unrelated customer's domain.
    step('certificate', op='order', id='order-x', owner='team-b',
         names=[HOST, OTHER], at=487)
    return db


def add_fork_evidence(db):
    # 08:05 four authoritative servers: two still answer C, two answer NEW.
    # They are appended through the ledger API so the append-only hash chain
    # is constructed in arrival order rather than hand-written.
    dns = [
        ('ns1', 'C', 485), ('ns2', 'C', 485),
        ('ns3', 'NEW', 485), ('ns4', 'NEW', 485),
    ]
    for view, value, claimed in dns:
        body = json.dumps({'host': HOST, 'type': 'TXT', 'value': value},
                          sort_keys=True)
        out = da.add_evidence(db, f'dns-{view}', HOST, 'authoritative_dns',
                              f'{view}.authority', view, claimed, claimed,
                              body, seal=DNS_SEAL, seal_key_id='witness-1',
                              note='sealed authoritative capture')
        assert out['decision'] == 'appended', out


class DisputeArchiveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'state.sqlite')
        self.db = build_disputed_db(self.path)
        add_fork_evidence(self.db)
        self.grant = da.issue_grant(self.db, 'g-1', 'lawyer-a', HOST,
                                    '/dispute', 470, 120, EXPORT_KEY)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    # -- trajectory 1 ----------------------------------------------------- #
    def test_forked_authoritative_answers_keep_local_and_external_apart(self):
        fork = da.dns_fork(self.db, HOST)
        self.assertTrue(fork['forked'])
        self.assertEqual(set(fork['answers']), {'C', 'NEW'})
        # Both viewpoints are preserved; neither fork may be presented alone.
        self.assertEqual(
            sum(len(v) for v in fork['answers'].values()), 4)

        chain = da.event_chain(self.db, HOST)
        # Exact structural selection reports how many events were scanned, so
        # the archive can show no event mentioning the host was skipped.
        self.assertGreaterEqual(chain['scanned'], chain['matched'])
        self.assertEqual(chain['matched'], len(chain['entries']))
        # A bare label that is only a substring of the host is not matched,
        # unlike the old LIKE search.
        decoy = da.host_events(self.db, 'disputed')
        self.assertEqual(decoy['matched'], 0)
        self.assertGreater(decoy['scanned'], 0)

        # The 08:00 local prove carries an authority gap: it compared only the
        # caller challenge, and the 08:05 answers were forked anyway.
        gaps = da.authority_gaps(self.db, HOST)
        self.assertTrue(gaps)
        self.assertEqual(gaps[0]['challenge'], 'C')
        self.assertIn('forked_answers', gaps[0])

        # A later, stabilised NEW answer must not overwrite the earlier fork.
        later = json.dumps({'host': HOST, 'type': 'TXT', 'value': 'NEW'},
                           sort_keys=True)
        da.add_evidence(self.db, 'dns-stable', HOST, 'authoritative_dns',
                        'ns1.authority', 'ns1', 500, 500, later,
                        seal=DNS_SEAL, seal_key_id='witness-1',
                        note='post-convergence answer')
        fork2 = da.dns_fork(self.db, HOST)
        self.assertTrue(fork2['forked'])  # the 08:05 split is still on record
        self.assertEqual(set(fork2['answers']), {'C', 'NEW'})

        # Local replay succeeds but stays explicitly scoped to local state.
        replay = da.local_replay(self.db, HOST)
        self.assertTrue(replay['verified'])
        self.assertEqual(replay['conclusion_scope'], 'local_state')

    # -- trajectory 2 ----------------------------------------------------- #
    def test_late_transfer_receipt_is_appended_not_reordered(self):
        before = da.event_chain(self.db, HOST)
        # 08:02 乙's registrar acceptance (sealed), 08:12 effective receipt
        # arriving late, bearing on the 08:07 delegation (event seq 7).
        accept = json.dumps({'host': HOST, 'applicant': 'yi',
                             'action': 'transfer_accepted'}, sort_keys=True)
        r1 = da.add_evidence(self.db, 'reg-accept', HOST, 'registrar',
                             'registrar.example', 'registrar', 482, 482,
                             accept, seal=REGISTRAR_SEAL,
                             seal_key_id='witness-1', note='yi accepted')
        self.assertEqual(r1['decision'], 'appended')
        receipt = json.dumps({'host': HOST, 'action': 'transfer_effective'},
                             sort_keys=True)
        r2 = da.add_evidence(self.db, 'reg-effective', HOST, 'registrar',
                             'registrar.example', 'registrar', 492, 492,
                             receipt, seal=REGISTRAR_SEAL,
                             seal_key_id='witness-1', affects_seq=7,
                             note='late effective receipt re: delegation event')
        self.assertEqual(r2['decision'], 'appended')
        self.assertTrue(r2['appended_after_existing'])

        # Old local sequence, inputs and results are byte-for-byte unchanged.
        after = da.event_chain(self.db, HOST)
        self.assertEqual(before['entries'], after['entries'])
        self.assertEqual(before['root'], after['root'])

        # The late receipt sits at the tail of an intact evidence chain and
        # declares which prior judgment it affects without altering it.
        ev = da.evidence_chain(self.db, HOST)
        self.assertTrue(ev['verified'])
        self.assertEqual(ev['entries'][-1]['evidence_id'], 'reg-effective')
        linked = rows(self.db,
                      "SELECT affects_seq FROM dispute_evidence "
                      "WHERE evidence_id='reg-effective'")[0]
        self.assertEqual(linked['affects_seq'], 7)

    # -- trajectory 3 ----------------------------------------------------- #
    def test_cached_query_timestamp_forgery_is_flagged_not_backdated(self):
        # 甲's agent submits a cached query stamped 08:04 but only received at
        # 08:30, with no independent seal.
        cached = json.dumps({'host': HOST, 'value': 'C',
                             'source': 'resolver-cache'}, sort_keys=True)
        r = da.add_evidence(self.db, 'cache-late', HOST, 'cached_dns',
                            'agent-a-laptop', 'cache-view', 484, 510, cached,
                            note='agent-submitted cached query')
        self.assertEqual(r['decision'], 'appended')
        self.assertIn('timestamp_unauthenticated', r['flags'])

        # Chain position follows arrival (received) order, not the claimed
        # 08:04 timestamp, so history cannot be backdated.
        ev = da.evidence_chain(self.db, HOST)
        self.assertTrue(ev['verified'])
        ids = [e['evidence_id'] for e in ev['entries']]
        self.assertEqual(ids[-1], 'cache-late')
        self.assertLess(
            next(e for e in ev['entries'] if e['evidence_id'] == 'dns-ns1')
            ['received_at'], 510)

        # A sealed registrar record with an older timestamp is not flagged.
        accept = json.dumps({'host': HOST, 'action': 'transfer_accepted'},
                            sort_keys=True)
        sealed = da.add_evidence(self.db, 'reg-2', HOST, 'registrar',
                                 'registrar.example', 'registrar', 482, 483,
                                 accept, seal=REGISTRAR_SEAL,
                                 seal_key_id='witness-1')
        self.assertEqual(sealed['flags'], [])

    # -- trajectory 4 ----------------------------------------------------- #
    def test_unrelated_domain_is_masked_without_breaking_verification(self):
        minimal = da.build_package(self.db, 'pkg-min', HOST, 'g-1', 490,
                                   'minimal', EXPORT_KEY, WITNESS_KEY)
        self.assertEqual(minimal['decision'], 'exported')
        pkg = minimal['package']
        blob = json.dumps(pkg, ensure_ascii=False)
        # The unrelated customer's full name and private identifiers never
        # appear anywhere in 甲's minimal copy.
        self.assertNotIn('other-customer.example', blob)
        self.assertNotIn('other-customer', blob)
        # The disputed host itself remains visible.
        self.assertIn(HOST, blob)

        # No raw original bytes leave in the minimal package.
        self.assertTrue(all(e['raw_bytes_b64'] is None
                            for e in pkg['evidence']))
        # Redaction commitments exist and cover the cross-domain order; only a
        # field count is exposed, never the hidden host names themselves.
        self.assertTrue(pkg['manifest']['redactions'])
        redacted_seqs = {m['seq'] for m in pkg['manifest']['redactions']}
        self.assertIn(7, redacted_seqs)  # seq 7 is the cross-domain order
        order_event = next(e for e in pkg['events'] if e['seq'] == 7)
        self.assertEqual(order_event['redacted_field_count'], 1)
        self.assertNotIn('redacted_hosts', order_event)

        # The package still verifies offline: chain continuity and commitments.
        result = da.verify_package(pkg, EXPORT_KEY, WITNESS_KEY)
        self.assertTrue(result['verified'], result['problems'])
        self.assertIsNone(result['ownership_ruling'])

        # The original (sealed-room) package contains the bytes and verifies
        # against the same commitments, so a custodian can open them later.
        original = da.build_package(self.db, 'pkg-orig', HOST, 'g-1', 491,
                                    'original', EXPORT_KEY, WITNESS_KEY)
        self.assertEqual(original['decision'], 'exported')
        opkg = original['package']
        self.assertIn('other-customer.example',
                      json.dumps(opkg, ensure_ascii=False))
        self.assertTrue(any(e['raw_bytes_b64'] for e in opkg['evidence']))
        self.assertTrue(da.verify_package(opkg, EXPORT_KEY,
                                          WITNESS_KEY)['verified'])
        # Same event root: masking fields does not fork the timeline.
        self.assertEqual(minimal['event_root'], original['event_root'])

        # Tampering with a disclosed event is detected by the validator.
        tampered = json.loads(json.dumps(pkg))
        tampered['events'][0]['result']['decision'] = 'forged'
        bad = da.verify_package(tampered, EXPORT_KEY, WITNESS_KEY)
        self.assertFalse(bad['verified'])
        self.assertTrue(any('result_hash' in p for p in bad['problems']))

    # -- trajectory 5 ----------------------------------------------------- #
    def test_export_requires_unexpired_signed_grant_and_leaves_receipt(self):
        # Knowing only the host name, with no grant, export is refused.
        denied = da.build_package(self.db, 'pkg-denied', HOST,
                                  'no-such-grant', 490, 'original',
                                  EXPORT_KEY, WITNESS_KEY)
        self.assertEqual(denied['decision'], 'unknown_grant')

        # A grant for a different host cannot be used.
        da.issue_grant(self.db, 'g-other', 'lawyer-a', OTHER, '/dispute',
                       470, 120, EXPORT_KEY)
        wrong = da.build_package(self.db, 'pkg-wrong', HOST, 'g-other', 490,
                                 'original', EXPORT_KEY, WITNESS_KEY)
        self.assertEqual(wrong['decision'], 'grant_host_mismatch')

        # An expired grant is refused and verification at a later time flags it.
        da.issue_grant(self.db, 'g-short', 'lawyer-a', HOST, '/dispute',
                       470, 10, EXPORT_KEY)
        expired = da.build_package(self.db, 'pkg-exp', HOST, 'g-short', 500,
                                   'original', EXPORT_KEY, WITNESS_KEY)
        self.assertEqual(expired['decision'], 'grant_expired')

        ok = da.build_package(self.db, 'pkg-ok', HOST, 'g-1', 490,
                              'original', EXPORT_KEY, WITNESS_KEY)
        self.assertEqual(ok['decision'], 'exported')
        late_check = da.verify_package(ok['package'], EXPORT_KEY,
                                       WITNESS_KEY, at=1000)
        self.assertIn('grant_expired_at_verification_time',
                      late_check['problems'])

        # A signed, queryable receipt records who downloaded what and when.
        receipt = rows(self.db,
                       "SELECT * FROM dispute_receipts WHERE package_id='pkg-ok'")[0]
        self.assertEqual(receipt['host'], HOST)
        self.assertEqual(receipt['mode'], 'original')
        self.assertTrue(receipt['signature'])

        # Revocation takes effect immediately.
        self.assertEqual(da.revoke_grant(self.db, 'g-1')['decision'],
                         'revoked')
        self.assertEqual(
            da.build_package(self.db, 'pkg-after-revoke', HOST, 'g-1', 492,
                             'original', EXPORT_KEY,
                             WITNESS_KEY)['decision'], 'grant_revoked')

        # A forged grant signature is rejected even if the row exists.
        self.assertFalse(da.verify_package(ok['package'], b'wrong-key',
                                           WITNESS_KEY)['verified'])

    # -- trajectory 6 ----------------------------------------------------- #
    def test_evidence_appends_keep_old_timeline_immutable_and_consistent(self):
        first = da.build_package(self.db, 'pkg-a', HOST, 'g-1', 490,
                                 'original', EXPORT_KEY, WITNESS_KEY)
        root_a = first['event_root']
        ev_root_a = first['evidence_root']

        # New evidence arrives after the first export.
        late = json.dumps({'host': HOST, 'action': 'transfer_effective'},
                          sort_keys=True)
        da.add_evidence(self.db, 'reg-late-2', HOST, 'registrar',
                        'registrar.example', 'registrar', 492, 495, late,
                        seal=REGISTRAR_SEAL, seal_key_id='witness-1',
                        affects_seq=7, note='arrived after first export')
        second = da.build_package(self.db, 'pkg-b', HOST, 'g-1', 496,
                                  'minimal', EXPORT_KEY, WITNESS_KEY)

        # The local event chain root is unchanged: new evidence only extends
        # the separate evidence ledger.
        self.assertEqual(second['event_root'], root_a)
        self.assertNotEqual(second['evidence_root'], ev_root_a)

        # Both packages verify independently and the guard sees one chain with
        # no contradictory timeline branch.
        self.assertTrue(da.verify_package(first['package'], EXPORT_KEY,
                                          WITNESS_KEY)['verified'])
        self.assertTrue(da.verify_package(second['package'], EXPORT_KEY,
                                          WITNESS_KEY)['verified'])
        guard = da.export_timeline_guard(self.db, HOST)
        self.assertTrue(guard['single_chain'])
        self.assertEqual(guard['conflicting_packages'], [])
        exported_ids = {e['package_id'] for e in guard['exports']}
        self.assertEqual(exported_ids, {'pkg-a', 'pkg-b'})

        # An invented branch root is detected if one is smuggled into exports.
        self.db.execute(
            "INSERT INTO dispute_exports VALUES('pkg-fake',?,'original',"
            "'g-1',497,1,'deadbeef',0,'')", (HOST,))
        guarded = da.export_timeline_guard(self.db, HOST)
        self.assertFalse(guarded['single_chain'])
        self.assertEqual(guarded['conflicting_packages'], ['pkg-fake'])

    def test_policy_separates_original_verification_from_commitments(self):
        pkg = da.build_package(self.db, 'pkg-policy', HOST, 'g-1', 490,
                               'minimal', EXPORT_KEY,
                               WITNESS_KEY)['package']
        policy = pkg['manifest']['policy']
        # External facts about the world require originals/custodian.
        self.assertIn('authoritative_dns_answer',
                      policy['must_be_verified_against_originals'])
        self.assertIn('registrar_transfer_effective_receipt',
                      policy['must_be_verified_against_originals'])
        # Local continuity and hidden-field presence are provable by commitment.
        self.assertIn('local_event_order_and_result',
                      policy['provable_by_commitment'])
        self.assertTrue(
            policy['original_custodian_required_for_minimal'])


if __name__ == '__main__':
    unittest.main()
