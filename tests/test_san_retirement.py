"""Verifiable SAN-retirement / shared-certificate handoff tests.

These tests exercise the four independent state planes called out by the
scenario:

* per-domain holder / scope / generation / revocation-time adjudication,
* serial wide certificate + single private-key reality,
* per gateway generation load and SNI evidence (with late reports),
* individual client connections crossing the revocation instants,

and both permitted completion routes, power-loss replay, re-delegation and
gateway generation rebuild.  Everything runs on an in memory/temp SQLite
database; no network, DNS, CA or cluster is contacted.
"""

import json
import tempfile
import unittest
from pathlib import Path

import edgehandoff
from edgehandoff import san_retirement as sr
from edgehandoff.store import connect, execute, replay, one, rows

ROOT = Path(__file__).resolve().parents[1]
assert Path(edgehandoff.__file__).resolve().is_relative_to(ROOT)

A = "api.a.example"
B = "api.b.example"
HOLDER_A = "holder-a"
HOLDER_B = "holder-b"
PLATFORM = "platform"
CERT_C = "C"
CERT_B = "CB"


class Harness:
    """Small scenario builder with its own temp database."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "san.sqlite")
        self.db = connect(self.path)
        self.n = 0

    def close(self):
        self.db.close()
        self.tmp.cleanup()

    def exe(self, subsystem, op, **fields):
        self.n += 1
        return execute(self.db, subsystem,
                       dict(request_id=f"r-{self.n}", op=op, **fields))

    def san(self, op, **fields):
        return self.exe("san_retirement", op, **fields)

    def dec(self, op, **fields):
        return self.san(op, **fields)["decision"]

    # -- canonical scene from the statement of facts -----------------------
    def seed(self, connections=True):
        for host, holder, lease in ((A, HOLDER_A, 100), (B, HOLDER_B, 80)):
            self.exe("ownership", "claim", host=host, holder=holder, epoch=1,
                     lease_until=lease, challenge="ch-" + host, at=1)
            self.exe("ownership", "prove", host=host, epoch=1,
                     challenge="ch-" + host, at=2)
        self.exe("ownership", "delegate", id="dA", host=A, grantor=HOLDER_A,
                 grantee=PLATFORM, scope="/", until_ts=90, at=3)
        self.exe("ownership", "delegate", id="dB", host=B, grantor=HOLDER_B,
                 grantee=PLATFORM, scope="/", until_ts=80, at=3)
        self.exe("certificate", "gateway", id="G1", epoch=1)
        self.exe("certificate", "gateway", id="G2", epoch=1)
        self.exe("certificate", "order", id="order-C", owner=PLATFORM,
                 names=[A, B], at=4)
        self.exe("certificate", "issue", order="order-C", serial=CERT_C,
                 not_before=5, expires=80)
        for gw in ("G1", "G2"):
            self.exe("certificate", "deploy", id=f"dep-c-{gw}", serial=CERT_C,
                     gateway=gw, gateway_epoch=1, at=6)
        if connections:
            self.san("connect", id="conn-a-g2", gateway="G2", sni=A,
                     serial=CERT_C, at=10, client="a-client")
            self.san("connect", id="conn-b-g2", gateway="G2", sni=B,
                     serial=CERT_C, at=11, client="b-client-2")
            self.san("connect", id="conn-b-g1", gateway="G1", sni=B,
                     serial=CERT_C, at=12, client="b-client-1")
        return self

    def revoke_a(self, at=20):
        return self.exe("ownership", "revoke_delegate", host=A, id="dA",
                        grantor=HOLDER_A, at=at)

    def issue_b_only(self, at=22, serial=CERT_B):
        self.exe("certificate", "order", id="order-B", owner=PLATFORM,
                 names=[B], at=at)
        return self.exe("certificate", "issue", order="order-B", serial=serial,
                        not_before=at, expires=79)

    # -- the two permitted completion routes ------------------------------
    def run_route1(self):
        self.revoke_a(20)
        self.san("start", case="case-1", serial=CERT_C, at=20)
        self.san("route", case="case-1", route="reissue_first", at=20)
        # G1 positively removes C at 21.
        self.san("report", id="rep-g1-remove-c", gateway="G1",
                 gateway_epoch=1, serial=CERT_C, loaded=False, at=21)
        self.san("offline", gateway="G2", at=21)
        self.issue_b_only(at=22)
        # First attempt toward offline G2 fails without creating a receipt.
        failed = self.san("deploy_b", case="case-1", serial=CERT_B,
                          id="dep-b-g2", gateway="G2", gateway_epoch=1, at=23)
        self.san("recover", gateway="G2", at=24)
        self.san("deploy_b", case="case-1", serial=CERT_B, id="dep-b-g1",
                 gateway="G1", gateway_epoch=1, at=25)
        self.san("deploy_b", case="case-1", serial=CERT_B, id="dep-b-g2",
                 gateway="G2", gateway_epoch=1, at=25)
        for gw in ("G1", "G2"):
            self.san("report", id=f"sni-{gw}", gateway=gw, gateway_epoch=1,
                     loads=[{"serial": CERT_B, "sni": [B]}], at=26)
        self.san("connect", id="new-b-g1", gateway="G1", sni=B,
                 serial=CERT_B, at=26)
        self.san("connect", id="new-b-g2", gateway="G2", sni=B,
                 serial=CERT_B, at=26)
        self.san("close", id="conn-b-g1", at=27, reason="migrated_to_B_only")
        self.san("close", id="conn-b-g2", at=27, reason="migrated_to_B_only")
        self.san("terminate_a", case="case-1", at=27)
        self.san("verify_b", case="case-1", at=27)
        revoked = self.san("revoke_shared", case="case-1", at=28)
        self.san("report", id="rep-g2-remove-c", gateway="G2",
                 gateway_epoch=1, serial=CERT_C, loaded=False, at=29)
        completed = self.san("complete", case="case-1", at=30)
        return failed, revoked, completed

    def run_route2(self):
        self.revoke_a(20)
        self.san("start", case="case-2", serial=CERT_C, at=20)
        self.san("route", case="case-2", route="quarantine_drain", at=20)
        self.san("report", id="rep-g1-remove-c", gateway="G1",
                 gateway_epoch=1, serial=CERT_C, loaded=False, at=21)
        self.san("quarantine", gateway="G2", case="case-2", at=21)
        self.san("offline", gateway="G2", at=21)
        blocked = self.san("connect", id="new-b-during-blackout",
                           gateway="G2", sni=B, serial=CERT_C, at=22)
        draining = self.san("drain", case="case-2", at=30)
        # G2 reconnects at 40 and back-fills an observation from t=25.
        late = self.san("late_report", id="rep-g2-backfill", gateway="G2",
                        gateway_epoch=1, serial=CERT_C, loaded=True,
                        at=25, received_at=40)
        for cid in ("conn-b-g1", "conn-b-g2", "conn-a-g2"):
            self.san("close", id=cid, at=42, reason="drained_naturally")
        drained = self.san("drain", case="case-2", at=42)
        revoked = self.san("revoke_shared", case="case-2", at=44)
        self.issue_b_only(at=45)
        self.san("deploy_b", case="case-2", serial=CERT_B, id="dep-b-g1",
                 gateway="G1", gateway_epoch=1, at=46)
        self.san("deploy_b", case="case-2", serial=CERT_B, id="dep-b-g2",
                 gateway="G2", gateway_epoch=1, at=46)
        self.san("report", id="rep-g2-remove-c", gateway="G2",
                 gateway_epoch=1, serial=CERT_C, loaded=False, at=46)
        self.san("lift_quarantine", gateway="G2", at=47)
        new_b = self.san("connect", id="new-b-g2", gateway="G2", sni=B,
                         serial=CERT_B, at=48)
        completed = self.san("complete", case="case-2", at=49)
        return blocked, draining, late, drained, revoked, new_b, completed

    def replayed_db(self):
        target = connect(":memory:")
        for event in rows(self.db, "SELECT subsystem,input FROM events ORDER BY seq"):
            execute(target, event["subsystem"], json.loads(event["input"]))
        return target


class SanRetirementTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()

    def tearDown(self):
        self.h.close()

    # ------------------------------------------------------------------ basics
    def test_dispatch_and_entrypoints(self):
        h = self.h
        h.seed(connections=False)
        # The subsystem is registered under its module name and synonyms.
        for subsystem in ("san_retirement", "retirement", "san"):
            result = execute(h.db, subsystem,
                             {"request_id": f"dispatch-{subsystem}",
                              "op": "status", "serial": CERT_C})
            self.assertIn("gateways", result)
        self.assertTrue(callable(sr.run))
        self.assertTrue(callable(sr.adjudicate_host))
        self.assertIs(sr.rights_at, sr.adjudicate_host)
        self.assertTrue(callable(sr.handoff_status))
        self.assertTrue(callable(sr.status))
        facade = sr.SanRetirement(h.db)
        self.assertTrue(callable(facade.adjudicate))

    # ------------------------------------------------------- per-domain truth
    def test_independent_holder_scope_generation_and_revocation_time(self):
        h = self.h.seed()
        h.revoke_a(20)
        a = sr.adjudicate_host(h.db, A, 25, owner=PLATFORM)
        b = sr.adjudicate_host(h.db, B, 25, owner=PLATFORM)

        self.assertFalse(a["authorized"])
        self.assertEqual(a["state"], "delegation_revoked")
        self.assertEqual(a["holder"], HOLDER_A)
        self.assertEqual(a["claim_epoch"], 1)
        self.assertEqual(a["scope"], "/")
        self.assertEqual(a["delegation_id"], "dA")
        self.assertEqual(a["revoked_at"], 20)

        self.assertTrue(b["authorized"])
        self.assertEqual(b["state"], "delegated")
        self.assertEqual(b["holder"], HOLDER_B)
        self.assertEqual(b["claim_epoch"], 1)
        self.assertEqual(b["delegation_id"], "dB")
        self.assertIsNone(b["revoked_at"])
        self.assertEqual(b["delegation_until"], 80)

        # B's independent lease/delegation end is adjudicated on its own.
        self.assertTrue(sr.adjudicate_host(h.db, B, 80, PLATFORM)["authorized"])
        self.assertFalse(sr.adjudicate_host(h.db, B, 81, PLATFORM)["authorized"])

    def test_rights_reconstruct_then_current_truth(self):
        h = self.h.seed()
        # The full event log already contains the future t=20 revocation, but
        # adjudication at t=15 must still report the delegation as live.
        before = sr.adjudicate_host(h.db, A, 15, owner=PLATFORM)
        self.assertTrue(before["authorized"])
        self.assertEqual(before["state"], "delegated")
        self.assertGreater(before["revoked_at"], 15) if before["revoked_at"] else None
        h.revoke_a(20)
        at20 = sr.adjudicate_host(h.db, A, 20, owner=PLATFORM)
        self.assertFalse(at20["authorized"])  # effective at the revocation instant

    def test_revocation_keeps_order_validation_and_b_order_accepted(self):
        h = self.h.seed()
        h.revoke_a(20)
        bad = h.exe("certificate", "order", id="order-with-a", owner=PLATFORM,
                    names=[A, B], at=21)
        self.assertEqual(bad["decision"], "unowned_san")
        self.assertIsNone(one(h.db, "SELECT id FROM orders WHERE id=?",
                              ("order-with-a",)))
        good = h.exe("certificate", "order", id="order-b-only", owner=PLATFORM,
                     names=[B], at=21)
        self.assertEqual(good["decision"], "accepted")

    def test_verdict_or_san_bit_cannot_withdraw_shared_private_key(self):
        h = self.h.seed()
        h.revoke_a(20)
        h.san("adjudicate", case="case-x", host=A, at=20, owner=PLATFORM)
        # Adjudication changes no certificate or gateway reality.
        self.assertEqual(one(h.db, "SELECT status FROM certificates WHERE serial=?",
                             (CERT_C,))["status"], "active")
        status = h.san("status", serial=CERT_C, at=21)
        self.assertEqual(status["gateways"]["G2"]["shared_serial_state"], "loaded")
        self.assertFalse(status["gates"]["key_withdrawn_every_gateway"])
        self.assertFalse(status["complete"])

    # --------------------------------------------------------- connections
    def test_new_a_connection_denied_even_though_gateway_still_serves_c(self):
        h = self.h.seed()
        h.revoke_a(20)
        result = h.san("connect", id="new-a", gateway="G2", sni=A,
                       serial=CERT_C, at=22)
        self.assertEqual(result["decision"], "domain_authorization_revoked")
        # Synonym vocabulary used by the prose names the same verdict.
        self.assertEqual(result["decision"], "delegation_revoked")
        self.assertFalse(result["admitted"])
        row = one(h.db, "SELECT * FROM sr_connections WHERE id='new-a'")
        self.assertEqual(row["physical"], 0)  # rejected handshake, not a session

    def test_observed_physical_a_session_is_marked_unauthorized(self):
        h = self.h.seed(connections=False)
        h.revoke_a(20)
        # G2's telemetry can still show a physically accepted A session on C.
        result = h.san("observe", id="phys-a", gateway="G2", sni=A,
                       serial=CERT_C, opened_at=23, at=24)
        self.assertEqual(result["decision"], "observed")
        self.assertFalse(result["authorized"])
        self.assertIn("unauthorized", result["classification"])

    def test_old_connections_cross_domain_and_serial_revocation(self):
        h = self.h.seed()
        h.revoke_a(20)
        old_a = one(h.db, "SELECT * FROM sr_connections WHERE id='conn-a-g2'")
        old_b = one(h.db, "SELECT * FROM sr_connections WHERE id='conn-b-g2'")

        standing_a = sr.connection_standing(h.db, old_a, at=25)
        standing_b = sr.connection_standing(h.db, old_b, at=25)
        self.assertEqual(standing_a["classification"], "domain_authorization_ended")
        self.assertFalse(standing_a["current_authorized"])
        self.assertEqual(standing_b["classification"], "legitimate")
        self.assertTrue(standing_b["current_authorized"])

        # A console wide serial revocation at 30 is not an A-only revoke.
        self.assertEqual(h.exe("certificate", "revoke", serial=CERT_C, at=30)["decision"],
                         "revoked")
        standing_b35 = sr.connection_standing(h.db, old_b, at=35)
        self.assertEqual(standing_b35["classification"],
                         "established_spanning_serial_revocation")
        self.assertTrue(standing_b35["spans_serial_revocation"])
        # B's domain right is still intact: never mislabelled as unauthorized.
        self.assertTrue(standing_b35["current_authorized"])
        self.assertEqual(standing_b35["right_state"], "delegated")

        # New handshakes on the now revoked serial are refused.
        new_b = h.san("connect", id="new-b-after-revoke", gateway="G2", sni=B,
                      serial=CERT_C, at=36)
        self.assertEqual(new_b["decision"], "certificate_revoked")
        self.assertEqual(new_b["decision"], "revoked")

        status = h.san("status", serial=CERT_C, at=35)
        by_id = {item["id"]: item for item in status["connections"]["records"]}
        self.assertEqual(by_id["conn-b-g2"]["classification"],
                         "established_spanning_serial_revocation")
        self.assertEqual(by_id["conn-a-g2"]["classification"],
                         "domain_authorization_ended")

    def test_console_serial_revocation_is_not_gateway_withdrawal(self):
        h = self.h.seed()
        h.exe("certificate", "revoke", serial=CERT_C, at=21)
        status = h.san("status", serial=CERT_C, at=22)
        self.assertTrue(status["gates"]["serial_revoked"])
        self.assertFalse(status["gates"]["key_withdrawn_every_gateway"])
        self.assertEqual(status["gateways"]["G2"]["shared_serial_state"], "loaded")
        self.assertEqual(status["certificate"]["revoked_at"], 21)

    # ------------------------------------------------- gateway evidence
    def test_g1_removal_and_g2_offline_late_backfill(self):
        h = self.h.seed(connections=False)
        g1 = h.san("report", id="g1-remove", gateway="G1", gateway_epoch=1,
                   serial=CERT_C, loaded=False, at=21)
        self.assertEqual(g1["decision"], "reported")
        status = h.san("status", serial=CERT_C, at=22)
        self.assertEqual(status["gateways"]["G1"]["shared_serial_state"], "removed")
        self.assertEqual(status["gateways"]["G2"]["shared_serial_state"], "loaded")

        h.san("offline", gateway="G2", at=21)
        late = h.san("late_report", id="g2-backfill", gateway="G2",
                     gateway_epoch=1, serial=CERT_C, loaded=True,
                     at=25, received_at=40)
        self.assertEqual(late["decision"], "reported")
        self.assertTrue(late["late"])
        report_row = one(h.db, "SELECT * FROM sr_reports WHERE id='g2-backfill'")
        self.assertEqual(report_row["late"], 1)
        self.assertEqual(report_row["observed_at"], 25)
        self.assertEqual(report_row["received_at"], 40)
        # The late fact proves the key was still loaded at its observation time.
        status = h.san("status", serial=CERT_C, at=40)
        self.assertEqual(status["gateways"]["G2"]["shared_serial_state"], "loaded")

        removed = h.san("report", id="g2-remove", gateway="G2", gateway_epoch=1,
                        serial=CERT_C, loaded=False, at=41)
        self.assertEqual(removed["decision"], "reported")
        status = h.san("status", serial=CERT_C, at=41)
        self.assertEqual(status["gateways"]["G2"]["shared_serial_state"], "removed")
        self.assertEqual(status["gateways"]["G2"]["shared_removed_at"], 41)
        self.assertTrue(status["gates"]["key_withdrawn_every_gateway"])
        self.assertTrue(replay(h.path)["verified"])

    def test_gateway_generation_rebuild_invalidates_old_evidence(self):
        h = self.h.seed(connections=False)
        # Rebuild G2 as generation 2.
        self.assertEqual(h.exe("certificate", "gateway", id="G2", epoch=2)["decision"],
                         "gateway_ready")
        status = h.san("status", serial=CERT_C, at=30)
        # Old epoch-1 deployment cannot prove anything about generation 2.
        self.assertEqual(status["gateways"]["G2"]["shared_serial_state"],
                         "stale_generation_state")
        self.assertFalse(status["gates"]["key_withdrawn_every_gateway"])

        stale = h.san("report", id="old-epoch-report", gateway="G2",
                      gateway_epoch=1, serial=CERT_C, loaded=False, at=31)
        self.assertEqual(stale["decision"], "stale_gateway")
        self.assertTrue(stale["stale"])
        status = h.san("status", serial=CERT_C, at=31)
        self.assertEqual(status["gateways"]["G2"]["epoch"], 2)
        self.assertEqual(status["gateways"]["G2"]["shared_serial_state"],
                         "stale_generation_state")

        # The rebuilt generation must supply its own positive evidence.
        fresh = h.san("report", id="new-epoch-clean", gateway="G2",
                      gateway_epoch=2, serial=CERT_C, loaded=False, at=32)
        self.assertEqual(fresh["decision"], "reported")
        status = h.san("status", serial=CERT_C, at=32)
        self.assertEqual(status["gateways"]["G2"]["shared_serial_state"], "removed")

    def test_natural_report_conflict_and_request_id_idempotency(self):
        h = self.h.seed(connections=False)
        first = h.san("report", id="same-receipt", gateway="G1",
                      gateway_epoch=1, serial=CERT_C, loaded=False, at=21)
        self.assertEqual(first["decision"], "reported")
        second = h.san("report", id="same-receipt", gateway="G1",
                       gateway_epoch=1, serial=CERT_C, loaded=False, at=22)
        self.assertEqual(second["decision"], "report_conflict")
        self.assertEqual(second["decision"], "receipt_conflict")

        step = {"request_id": "idempotent-1", "op": "offline", "gateway": "G2", "at": 21}
        r1 = execute(h.db, "san_retirement", dict(step))
        r2 = execute(h.db, "san_retirement", dict(step))
        self.assertEqual(r1["decision"], r2["decision"])
        posture_count = one(h.db, "SELECT COUNT(*) c FROM sr_posture WHERE gateway='G2'")["c"]
        self.assertEqual(posture_count, 1)
        conflict = execute(h.db, "san_retirement",
                           dict(step, at=22))
        self.assertEqual(conflict["decision"], "request_conflict")

    # ----------------------------------------------------- B deploy failure
    def test_b_only_deployment_offline_failure_retry_and_epoch_mismatch(self):
        h = self.h.seed(connections=False)
        h.revoke_a(20)
        h.issue_b_only(22)
        h.san("offline", gateway="G2", at=21)
        failed = h.san("deploy_b", serial=CERT_B, id="b-dep-g2", gateway="G2",
                       gateway_epoch=1, at=23)
        self.assertEqual(failed["decision"], "gateway_unreachable")
        # The failure vocabulary also matches the generic deploy denial.
        self.assertEqual(failed["decision"], "deploy_denied")
        self.assertIsNone(one(
            h.db, "SELECT id FROM deployments WHERE id='b-dep-g2'"))
        # A retry with a new request id but the same receipt id succeeds once
        # the gateway is reachable; the failed attempt inserted nothing.
        h.san("recover", gateway="G2", at=24)
        ok = h.san("deploy_b", serial=CERT_B, id="b-dep-g2", gateway="G2",
                   gateway_epoch=1, at=25)
        self.assertEqual(ok["decision"], "deployed")

        # Gateway generation mismatch is still the subsystem's deploy_denied.
        h.exe("certificate", "gateway", id="G1", epoch=2)
        bad_epoch = h.san("deploy_b", serial=CERT_B, id="b-dep-g1-old",
                          gateway="G1", gateway_epoch=1, at=26)
        self.assertEqual(bad_epoch["decision"], "deploy_denied")

    # ------------------------------------------------------------ route one
    def test_route1_reissue_first_keeps_b_served_and_completes(self):
        h = self.h.seed()
        failed, revoked, completed = h.run_route1()
        self.assertEqual(failed["decision"], "gateway_unreachable")
        self.assertEqual(revoked["decision"], "revoked")
        self.assertEqual(completed["decision"], "complete")

        status = h.san("status", case="case-1", at=30)
        self.assertTrue(status["complete"], status["blockers"])
        gates = status["gates"]
        self.assertTrue(gates["revoked_rights_dead"])
        self.assertTrue(gates["surviving_rights_valid"])
        self.assertTrue(gates["serial_revoked"])
        self.assertTrue(gates["key_withdrawn_every_gateway"])
        self.assertTrue(gates["b_certificate_every_gateway"])
        self.assertTrue(gates["b_sni_every_gateway"])
        self.assertTrue(gates["b_traffic_on_new_certificate"])
        self.assertTrue(gates["revoked_connections_explicitly_terminated"])

        # A's physical old session was explicitly terminated; B's migrated.
        conn_a = one(h.db, "SELECT end_reason,closed_at FROM sr_connections WHERE id='conn-a-g2'")
        self.assertTrue(conn_a["end_reason"].startswith("terminated"))
        self.assertIsNotNone(conn_a["closed_at"])
        for cid in ("conn-b-g1", "conn-b-g2"):
            row = one(h.db, "SELECT end_reason FROM sr_connections WHERE id=?", (cid,))
            self.assertEqual(row["end_reason"], "migrated_to_B_only")

        # Ordering evidence: B verified before serial revocation, removal after.
        kinds = [r["kind"] for r in rows(
            h.db, "SELECT kind FROM sr_actions WHERE case_id='case-1' ORDER BY seq")]
        self.assertLess(kinds.index("verify_b"), kinds.index("revoke_shared"))
        self.assertLess(kinds.index("revoke_shared"), kinds.index("complete"))
        self.assertTrue(replay(h.path)["verified"])

    def test_route1_accepts_revoke_then_terminate_order(self):
        h = self.h.seed()
        h.revoke_a(20)
        h.san("start", case="c", serial=CERT_C, at=20)
        h.san("route", case="c", route="reissue_first")
        h.san("report", id="rm1", gateway="G1", epoch=1, serial=CERT_C, loaded=False, at=21)
        h.issue_b_only(22)
        h.san("deploy_b", case="c", serial=CERT_B, id="b1", gateway="G1", at=25)
        h.san("deploy_b", case="c", serial=CERT_B, id="b2", gateway="G2", at=25)
        h.san("connect", id="nb1", gateway="G1", sni=B, serial=CERT_B, at=26)
        h.san("connect", id="nb2", gateway="G2", sni=B, serial=CERT_B, at=26)
        h.san("close", id="conn-b-g1", at=27, reason="migrated")
        h.san("close", id="conn-b-g2", at=27, reason="migrated")
        h.san("verify_b", case="c", at=27)
        # Serial revoke is allowed before A sessions are killed...
        self.assertEqual(h.san("revoke_shared", case="c", at=28)["decision"], "revoked")
        # ...but completion stays blocked until A is explicitly terminated.
        self.assertIn("revoked_connections_not_terminated",
                      h.san("complete", case="c", at=29).get("blockers", []))
        h.san("terminate_a", case="c", at=30)
        h.san("report", id="rm2", gateway="G2", epoch=1, serial=CERT_C, loaded=False, at=30)
        self.assertEqual(h.san("complete", case="c", at=31)["decision"], "complete")

    # ------------------------------------------------------------ route two
    def test_route2_blackout_blocks_new_b_on_both_entries(self):
        h = self.h.seed()
        h.revoke_a(20)
        h.san("start", case="k", serial=CERT_C, at=20)
        h.san("route", case="k", route="quarantine_drain")
        # G1 positively removes C at 21, so it can no longer present it.
        h.san("report", id="g1-rm", gateway="G1", epoch=1, serial=CERT_C,
              loaded=False, at=21)
        g1 = h.san("connect", id="b-new-g1", gateway="G1", sni=B, serial=CERT_C, at=22)
        self.assertEqual(g1["decision"], "certificate_not_loaded")
        # G2 still holds C but is isolated from the new-connection entry.
        h.san("quarantine", gateway="G2", at=21)
        g2 = h.san("connect", id="b-new-g2", gateway="G2", sni=B, serial=CERT_C, at=22)
        self.assertEqual(g2["decision"], "new_entries_isolated")
        # Both are rejected handshakes, never active sessions.
        self.assertEqual(one(h.db, "SELECT COUNT(*) c FROM sr_connections WHERE physical=1")["c"], 3)

    def test_route2_blackout_then_restore(self):
        h = self.h.seed()
        blocked, draining, late, drained, revoked, new_b, completed = h.run_route2()
        self.assertEqual(blocked["decision"], "new_entries_isolated")
        self.assertEqual(draining["decision"], "draining")
        self.assertEqual(late["decision"], "reported")
        self.assertEqual(drained["decision"], "drained")
        self.assertEqual(revoked["decision"], "revoked")
        self.assertEqual(new_b["decision"], "connected")
        self.assertEqual(completed["decision"], "complete")

        status = h.san("status", case="case-2", at=49)
        self.assertTrue(status["complete"], status["blockers"])
        self.assertTrue(status["gates"]["shared_connections_drained"])
        self.assertTrue(status["gates"]["b_new_entry_restored"])
        self.assertTrue(status["gates"]["key_withdrawn_every_gateway"])

        # Route two does not force the surviving holder's sessions: every old
        # connection ended through natural drain rather than termination.
        for cid in ("conn-a-g2", "conn-b-g1", "conn-b-g2"):
            row = one(h.db, "SELECT end_reason FROM sr_connections WHERE id=?", (cid,))
            self.assertEqual(row["end_reason"], "drained_naturally", cid)
        # The blackout denial was recorded and never counted as active.
        denied = one(h.db, "SELECT physical FROM sr_connections WHERE id='new-b-during-blackout'")
        self.assertEqual(denied["physical"], 0)
        self.assertTrue(replay(h.path)["verified"])

    def test_two_routes_share_original_but_differ_in_sequence_and_endings(self):
        h1 = Harness(); h2 = Harness()
        try:
            h1.seed(); h1.run_route1()
            h2.seed(); h2.run_route2()
            s1 = h1.san("status", case="case-1", at=30)
            s2 = h2.san("status", case="case-2", at=49)
            self.assertTrue(s1["complete"] and s2["complete"])

            # Same revocation original in both.
            for status in (s1, s2):
                self.assertEqual(status["revoked_hosts"], [A])
                self.assertEqual(status["domain_rights"][A]["revoked_at"], 20)
                self.assertFalse(status["domain_rights"][A]["authorized"])
                self.assertTrue(status["domain_rights"][B]["authorized"])

            # Route one serves B via CB before C is revoked; route two revokes
            # C first and only then brings B onto CB.
            c_revoke_1 = one(h1.db,
                "SELECT at FROM sr_actions WHERE case_id='case-1' AND kind='revoke_shared'")["at"]
            b_deploy_1 = one(h1.db,
                "SELECT MIN(at) at FROM sr_actions WHERE case_id='case-1' AND kind='deploy_b'")["at"]
            self.assertLess(b_deploy_1, c_revoke_1)

            c_revoke_2 = one(h2.db,
                "SELECT at FROM sr_actions WHERE case_id='case-2' AND kind='revoke_shared'")["at"]
            b_deploy_2 = one(h2.db,
                "SELECT MIN(at) at FROM sr_actions WHERE case_id='case-2' AND kind='deploy_b'")["at"]
            self.assertLess(c_revoke_2, b_deploy_2)

            a1 = one(h1.db, "SELECT end_reason FROM sr_connections WHERE id='conn-a-g2'")["end_reason"]
            a2 = one(h2.db, "SELECT end_reason FROM sr_connections WHERE id='conn-a-g2'")["end_reason"]
            self.assertTrue(a1.startswith("terminated"))
            self.assertEqual(a2, "drained_naturally")
        finally:
            h1.close(); h2.close()

    # --------------------------------------------------- re-delegation/replay
    def test_a_redelegation_cannot_revive_old_grant(self):
        h = self.h.seed(connections=False)
        h.revoke_a(20)
        # Re-sending the original delegation under a fresh request id cannot
        # re-insert or un-revoke the same delegation row.
        duplicate = h.exe("ownership", "delegate", id="dA", host=A,
                          grantor=HOLDER_A, grantee=PLATFORM, scope="/",
                          until_ts=95, at=50)
        self.assertEqual(duplicate["decision"], "delegation_conflict")
        # A holder is free to make a new, later generation delegation.
        again = h.exe("ownership", "delegate", id="dA-second", host=A,
                      grantor=HOLDER_A, grantee=PLATFORM, scope="/",
                      until_ts=95, at=51)
        self.assertEqual(again["decision"], "delegated")

        self.assertFalse(sr.adjudicate_host(h.db, A, 40, PLATFORM)["authorized"])
        late = sr.adjudicate_host(h.db, A, 60, PLATFORM)
        self.assertTrue(late["authorized"])
        self.assertEqual(late["delegation_id"], "dA-second")

        # Power-loss replay into an empty database must reach the same truth:
        # the old delegation stays dead at t=25 even though a new one exists.
        self.assertTrue(replay(h.path)["verified"])
        target = h.replayed_db()
        try:
            self.assertFalse(sr.adjudicate_host(target, A, 25, PLATFORM)["authorized"])
            replayed_late = sr.adjudicate_host(target, A, 60, PLATFORM)
            self.assertTrue(replayed_late["authorized"])
            self.assertEqual(replayed_late["delegation_id"], "dA-second")
            self.assertEqual(one(target, "SELECT revoked FROM delegations WHERE id='dA'")["revoked"], 1)
        finally:
            target.close()

    def test_same_serial_full_route_replay_converges(self):
        h = self.h.seed()
        h.run_route1()
        # Issuing the same serial again is a conflict, not a second key.
        h.exe("certificate", "order", id="order-dup", owner=PLATFORM,
              names=[B], at=31)
        dup_serial = h.exe("certificate", "issue", order="order-dup",
                           serial=CERT_C, not_before=32, expires=70)
        self.assertEqual(dup_serial["decision"], "serial_conflict")

        result = replay(h.path)
        self.assertTrue(result["verified"], result.get("divergence"))
        self.assertGreater(result["events"], 10)

        target = h.replayed_db()
        try:
            report = sr.evaluate(target, case_id="case-1", at=30)
            self.assertTrue(report["complete"], report["blockers"])
            copies = rows(target, "SELECT * FROM sr_copies WHERE serial=?", (CERT_C,))
            # Exactly one copy row per gateway generation/serial.
            self.assertEqual({(r["gateway"], r["loaded"]) for r in copies},
                             {("G1", 0), ("G2", 0)})
        finally:
            target.close()

    def test_sni_selection_evidence_and_single_key_fingerprint(self):
        h = self.h.seed(connections=False)
        status = h.san("status", serial=CERT_C, at=7)
        fps = {g: status["gateways"][g]["single_key_fingerprint"] for g in ("G1", "G2")}
        # One serial/private key means one fingerprint on every copy.
        self.assertEqual(len(set(fps.values())), 1)
        self.assertEqual(status["certificate"]["single_key_fingerprint"], fps["G1"])

        # A current-generation report that does not map SNI B to C causes the
        # connection cross-check to reject the mismatched selection.
        h.san("report", id="weird-sni", gateway="G1", gateway_epoch=1,
              loads=[{"serial": CERT_C, "sni": ["other.example"]}], at=8)
        denied = h.san("connect", id="sni-mismatch", gateway="G1", sni=B,
                       serial=CERT_C, at=9)
        self.assertEqual(denied["decision"], "sni_selection_mismatch")

    # ------------------------------------------------------------ cutover
    def test_cutover_a_blocks_but_b_advances_after_san_revocation(self):
        h = self.h.seed(connections=False)
        h.exe("cutover", "backend", id="old", epoch=1, healthy=True)
        h.exe("cutover", "backend", id="new", epoch=1, healthy=True)
        for host, pid in ((A, "plan-a"), (B, "plan-b")):
            locked = h.exe("cutover", "plan", id=pid, host=host, claim_epoch=1,
                           serial=CERT_C, gateway="G1", old_backend="old",
                           new_backend="new", at=8)
            self.assertEqual(locked["decision"], "locked")
            h.exe("cutover", "sample", id=f"s1-{pid}", plan=pid, stage=1,
                  at=8, healthy=True)
            self.assertEqual(h.exe("cutover", "advance", plan=pid, at=9)["decision"],
                             "advanced")
        h.revoke_a(20)
        h.exe("cutover", "sample", id="s2-a", plan="plan-a", stage=2, at=21, healthy=True)
        h.exe("cutover", "sample", id="s2-b", plan="plan-b", stage=2, at=21, healthy=True)
        # A's plan can no longer advance; B's plan on the SAME serial can.
        self.assertEqual(h.exe("cutover", "advance", plan="plan-a", at=22)["decision"],
                         "contract_changed")
        self.assertEqual(h.exe("cutover", "advance", plan="plan-b", at=22)["decision"],
                         "advanced")

    def test_b_only_certificate_can_lock_fresh_cutover_after_migration(self):
        h = self.h.seed(connections=False)
        h.revoke_a(20)
        h.issue_b_only(22)
        dep = h.san("deploy_b", serial=CERT_B, id="b-only-dep", gateway="G1",
                    gateway_epoch=1, at=25)
        self.assertEqual(dep["decision"], "deployed")
        h.exe("cutover", "backend", id="old", epoch=1, healthy=True)
        h.exe("cutover", "backend", id="new", epoch=1, healthy=True)
        plan = h.exe("cutover", "plan", id="plan-b-new-cert", host=B,
                     claim_epoch=1, serial=CERT_B, gateway="G1",
                     old_backend="old", new_backend="new", at=26)
        self.assertEqual(plan["decision"], "locked")

    def test_renewal_order_keeps_then_truth_but_cannot_launder_a(self):
        h = self.h.seed(connections=False)
        # The renewal order is accepted while both delegations are live...
        order = h.exe("certificate", "order", id="renew-order", owner=PLATFORM,
                      names=[A, B], at=15)
        self.assertEqual(order["decision"], "accepted")
        h.revoke_a(20)
        # ...history still says A was authorized at order time...
        self.assertTrue(sr.adjudicate_host(h.db, A, 15, PLATFORM)["authorized"])
        # ...but renewing the same two-name certificate after revocation is
        # refused rather than silently carrying A forward.
        renew = h.exe("certificate", "renew", predecessor=CERT_C,
                      order="renew-order", serial="C2", at=22,
                      not_before=22, expires=75)
        self.assertEqual(renew["decision"], "ownership_changed")
        self.assertIsNone(one(h.db, "SELECT serial FROM certificates WHERE serial='C2'"))
        # The accepted historical order artifact is preserved, not rewritten.
        self.assertEqual(one(h.db, "SELECT status FROM orders WHERE id='renew-order'")["status"],
                         "accepted")
        self.assertTrue(replay(h.path)["verified"])

    # ------------------------------------------------- holder own gateway
    def test_holder_own_gateway_cutover_is_independent_of_platform(self):
        h = self.h.seed(connections=False)
        h.revoke_a(20)
        # The holder's own right does not depend on the platform delegation.
        own_order = h.exe("certificate", "order", id="order-a-own",
                          owner=HOLDER_A, names=[A], at=21)
        self.assertEqual(own_order["decision"], "accepted")
        own_issue = h.exe("certificate", "issue", order="order-a-own",
                          serial="A-OWN-CERT", not_before=22, expires=95)
        self.assertEqual(own_issue["decision"], "issued")
        h.exe("certificate", "gateway", id="GA-own", epoch=1)
        own_deploy = h.exe("certificate", "deploy", id="dep-a-own",
                           serial="A-OWN-CERT", gateway="GA-own",
                           gateway_epoch=1, at=23)
        self.assertEqual(own_deploy["decision"], "deployed")
        # Platform still cannot serve new A sessions on the shared C.
        denied = h.san("connect", id="a-shared-denied", gateway="G1", sni=A,
                       serial=CERT_C, at=24)
        self.assertEqual(denied["decision"], "domain_authorization_revoked")
        # But A's holder-owned entry admits A independently.
        allowed = h.san("connect", id="a-own-allowed", gateway="GA-own", sni=A,
                        serial="A-OWN-CERT", at=24)
        self.assertEqual(allowed["decision"], "connected")


if __name__ == "__main__":
    unittest.main()
