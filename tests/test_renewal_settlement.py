import unittest

from edgehandoff.store import connect, one
from edgehandoff.registrar_payment import draft
from edgehandoff import renewal_settlement as rs


AMOUNT = 10_000
REGISTRAR_FEE = 7_000
COMMISSION = 1_000
DEPOSIT = 8_000
LOCAL_LEASE_UNTIL = 365
# The registry receipt says the term starts two time units before the local
# lease boundary and lasts one 365-unit year.
REGISTRY_FROM = LOCAL_LEASE_UNTIL - 2
REGISTRY_TO = REGISTRY_FROM + 365


class RenewalSettlementTrajectoryTest(unittest.TestCase):
    def setUp(self):
        self.db = connect(":memory:")
        rs.ensure_schema(self.db)
        rs.seed_platform_capital(self.db, 50_000)

    def tearDown(self):
        self.db.close()

    def make_case(self, plan="guaranteed", agent_id="agent-a", deposit=DEPOSIT):
        self.assertEqual(
            rs.sign_mandate(
                self.db, "mandate-1", "edge.example", "customer-1", agent_id,
                "customer-signed-domain-and-agent", 10,
            )["decision"],
            "mandate_signed",
        )
        result = rs.open_renewal(
            self.db, "case-1", "mandate-1", 20, plan=plan,
            local_lease_until=LOCAL_LEASE_UNTIL,
            requested_from=LOCAL_LEASE_UNTIL,
            requested_until=LOCAL_LEASE_UNTIL + 365,
            price_cents=AMOUNT, registrar_fee_cents=REGISTRAR_FEE,
            commission_cents=COMMISSION, deposit_cents=deposit,
        )
        self.assertEqual(result["decision"], "renewal_opened")
        return result

    def authorize(self, number):
        return rs.authorize_payment(
            self.db, f"payment-{number}", "case-1", AMOUNT, 20 + number,
            source_ref=f"bank-card-{number}", auth_ref=f"bank-auth-{number}",
        )

    def settle(self, number, at=None):
        return rs.settle_payment(
            self.db, f"payment-{number}", at or (22 + number),
            f"bank-settlement-{number}",
        )

    def first_payment_settled(self):
        self.assertEqual(self.authorize(1)["decision"], "authorized")
        result = self.settle(1, 22)
        self.assertEqual(result["decision"], "settled")
        self.assertEqual(result["applied_cents"], AMOUNT)
        self.assertEqual(
            one(self.db,
                "SELECT status FROM rs_bills WHERE bill_id='bill-customer-case-1'")["status"],
            "paid",
        )

    def second_authorization_held(self):
        self.assertEqual(self.authorize(2)["decision"], "authorized")

    def two_acceptance_numbers(self):
        first = rs.submit_to_registrar(
            self.db, "submission-1", "case-1", "ACCEPT-1", 30,
            request_id="agent-a-timeout-request",
            registrar_order_id="registrar-order-1",
        )
        second = rs.submit_to_registrar(
            self.db, "submission-2", "case-1", "ACCEPT-2", 31,
            request_id="agent-a-retry-request",
            registrar_order_id="registrar-order-1",
        )
        self.assertEqual(first["decision"], "accepted_pending")
        self.assertEqual(second["decision"], "accepted_pending")

    def promise_full_year(self):
        result = rs.issue_guaranteed_promise(self.db, "case-1", 25)
        self.assertEqual(result["decision"], "guaranteed_promised")
        self.assertEqual(result["valid_from"], 365)
        self.assertEqual(result["valid_to"], 730)
        return result

    def confirm_once(self, authentic=True, receipt_id="receipt-1",
                     registry_no="REGISTRY-RECEIPT-1", payment_id=None):
        return rs.confirm_registry_receipt(
            self.db, receipt_id, "case-1", "submission-1", registry_no,
            REGISTRY_FROM, REGISTRY_TO, 40, host="edge.example",
            authentic=authentic,
            evidence_digest="sha256:verified-registry-payload",
            payment_id=payment_id,
        )

    def pay_settlement_bills(self):
        self.assertEqual(
            rs.pay_bill(self.db, "bill-registrar-case-1", 50,
                        "registrar-b-wire-1")["decision"],
            "bill_paid",
        )
        self.assertEqual(
            rs.pay_bill(self.db, "bill-commission-case-1", 51,
                        "agent-a-commission-1")["decision"],
            "bill_paid",
        )

    # Trajectory 1 -------------------------------------------------------
    def test_01_duplicate_acceptance_numbers_do_not_buy_two_years(self):
        self.make_case("guaranteed")
        self.first_payment_settled()
        self.promise_full_year()
        self.two_acceptance_numbers()

        # Acceptance numbers are not registry renewals.
        self.assertEqual(rs.summary(self.db)["registered_entitlements"], 0)
        self.assertEqual(
            one(self.db, "SELECT COUNT(*) AS n FROM rs_submissions")["n"], 2)

        confirmed = self.confirm_once()
        self.assertEqual(confirmed["decision"], "renewal_confirmed")
        self.assertEqual(confirmed["valid_from"], REGISTRY_FROM)
        self.assertEqual(confirmed["valid_to"], REGISTRY_TO)

        registered = rs.entitlement(self.db, "case-1", "registered")
        self.assertEqual(registered["entitlement_id"], "ent-reg-case-1")
        self.assertEqual(registered["mandate_id"], "mandate-1")
        self.assertEqual(registered["registrar_order_id"], "registrar-order-1")
        self.assertEqual(registered["submission_id"], "submission-1")
        self.assertEqual(registered["registry_receipt_id"], "receipt-1")
        self.assertEqual(registered["payment_id"], "payment-1")
        self.assertEqual((registered["valid_from"], registered["valid_to"]),
                         (363, 728))
        self.assertEqual(rs.summary(self.db)["registered_entitlements"], 1)
        self.assertEqual(
            one(self.db,
                "SELECT status FROM rs_submissions WHERE submission_id='submission-2'"
                )["status"],
            "duplicate_acceptance",
        )

        self.pay_settlement_bills()
        distribution = rs.settlement_distribution(self.db, "case-1")
        self.assertEqual(distribution["platform_margin_cents"], 2_000)
        self.assertEqual(distribution["registrar_paid_cents"], 7_000)
        self.assertEqual(distribution["commission_paid_cents"], 1_000)
        self.assertEqual(distribution["commission_agent_id"], "agent-a")

        totals = rs.summary(self.db)
        self.assertEqual(totals["available_cash_cents"], 52_000)
        self.assertEqual(totals["locked_deposit_cents"], 0)
        self.assertEqual(totals["cash_total_cents"], 52_000)
        self.assertEqual(totals["registrar_payable_cents"], 0)
        self.assertEqual(totals["agent_commission_payable_cents"], 0)

    # Trajectory 2 -------------------------------------------------------
    def test_02_single_authentic_registry_receipt_is_upgrade_boundary(self):
        # The old subsystem accepts an arbitrary fee from a verified claim.
        self.db.execute(
            "INSERT INTO claims(host,holder,epoch,lease_until,challenge,status) "
            "VALUES('edge.example','customer-1',1,365,'dns-challenge','verified')"
        )
        self.assertEqual(
            draft(self.db, "old-draft-payment", "edge.example", 999)["decision"],
            "drafted",
        )

        self.make_case("confirmed_only")
        self.first_payment_settled()
        rs.submit_to_registrar(
            self.db, "submission-1", "case-1", "ACCEPT-1", 30,
            registrar_order_id="registrar-order-1",
        )

        unverified = self.confirm_once(
            authentic=False, receipt_id="receipt-unverified",
            registry_no="UNVERIFIED-1",
        )
        self.assertEqual(unverified["decision"], "evidence_unverified")
        self.assertIsNone(rs.entitlement(self.db, "case-1", "registered"))

        confirmed = self.confirm_once()
        self.assertEqual(confirmed["decision"], "renewal_confirmed")
        registered = rs.entitlement(self.db, "case-1", "registered")
        self.assertEqual((registered["valid_from"], registered["valid_to"]),
                         (LOCAL_LEASE_UNTIL - 2, LOCAL_LEASE_UNTIL - 2 + 365))

        # The local lease boundary is evidence for scheduling only and is not
        # rewritten to manufacture or erase renewal coverage.
        claim = one(self.db, "SELECT lease_until FROM claims WHERE host='edge.example'")
        self.assertEqual(claim["lease_until"], 365)

        self.pay_settlement_bills()
        totals = rs.summary(self.db)
        self.assertEqual(totals["registrar_cost_cents"], 7_000)
        self.assertEqual(totals["agent_commission_expense_cents"], 1_000)
        self.assertEqual(totals["available_cash_cents"], 52_000)

    # Trajectory 3 -------------------------------------------------------
    def test_03_second_hold_becomes_settlement_and_is_refunded(self):
        self.make_case("guaranteed")
        self.first_payment_settled()
        self.second_authorization_held()

        before = rs.summary(self.db)
        self.assertEqual(before["settled_customer_payments_cents"], 10_000)
        self.assertEqual(before["authorized_hold_cents"], 10_000)
        self.assertEqual(before["available_cash_cents"], 60_000)

        settled = self.settle(2, 24)
        self.assertEqual(settled["decision"], "settled")
        self.assertEqual(settled["overpayment_cents"], 10_000)
        self.assertEqual(
            rs.revoke_authorization(
                self.db, "payment-2", 241, "void-after-settlement"
            )["decision"],
            "authorization_not_revocable",
        )
        after_settlement = rs.summary(self.db)
        self.assertEqual(after_settlement["settled_customer_payments_cents"], 20_000)
        self.assertEqual(after_settlement["authorized_hold_cents"], 0)
        self.assertEqual(after_settlement["available_cash_cents"], 70_000)
        self.assertEqual(after_settlement["customer_overpayment_cents"], 10_000)

        self.promise_full_year()
        self.two_acceptance_numbers()
        confirmed = self.confirm_once(payment_id="payment-1")
        self.assertEqual(confirmed["decision"], "renewal_confirmed")
        self.assertEqual(confirmed["payment_id"], "payment-1")
        self.assertEqual(rs.summary(self.db)["registered_entitlements"], 1)

        refunded = rs.refund_payment(
            self.db, "refund-2", "payment-2", 45, "actual-refund-ref-2",
        )
        self.assertEqual(refunded["decision"], "refunded")
        self.assertTrue(refunded["refund_posted"])
        self.assertFalse(refunded["bank_return"])

        after_refund = rs.summary(self.db)
        self.assertEqual(after_refund["available_cash_cents"], 60_000)
        self.assertEqual(after_refund["customer_overpayment_cents"], 0)
        self.assertEqual(
            one(self.db, "SELECT status FROM rs_payments WHERE payment_id='payment-2'")["status"],
            "refunded",
        )
        self.assertEqual(
            one(self.db,
                "SELECT COUNT(*) AS n FROM rs_payment_events WHERE event_type='refund'")["n"],
            1,
        )

        # The duplicate customer payment does not reverse the one registrar fee.
        self.pay_settlement_bills()
        totals = rs.summary(self.db)
        self.assertEqual(totals["available_cash_cents"], 52_000)
        self.assertEqual(totals["registrar_cost_cents"], 7_000)
        self.assertEqual(totals["registrar_payable_cents"], 0)

    # Trajectory 4 -------------------------------------------------------
    def test_04_second_hold_is_revoked_without_fake_refund(self):
        self.make_case("confirmed_only")
        self.first_payment_settled()
        self.second_authorization_held()
        rs.submit_to_registrar(
            self.db, "submission-1", "case-1", "ACCEPT-1", 30,
            registrar_order_id="registrar-order-1",
        )
        self.assertEqual(self.confirm_once()["decision"], "renewal_confirmed")

        revoked = rs.revoke_authorization(
            self.db, "payment-2", 41, "bank-auth-void-2",
        )
        self.assertEqual(revoked["decision"], "authorization_revoked")
        self.assertFalse(revoked["refund_posted"])
        self.assertEqual(
            rs.settle_payment(
                self.db, "payment-2", 42, "attempted-capture-after-void"
            )["decision"],
            "payment_not_settleable",
        )

        payment = one(self.db, "SELECT status FROM rs_payments WHERE payment_id='payment-2'")
        self.assertEqual(payment["status"], "authorization_revoked")
        event_counts = {
            row["event_type"]: row["n"]
            for row in self.db.execute(
                "SELECT event_type, COUNT(*) AS n FROM rs_payment_events GROUP BY event_type"
            )
        }
        self.assertEqual(event_counts.get("authorization"), 2)
        self.assertEqual(event_counts.get("authorization_revocation"), 1)
        self.assertNotIn("refund", event_counts)
        self.assertNotIn("return", event_counts)

        totals = rs.summary(self.db)
        self.assertEqual(totals["available_cash_cents"], 60_000)
        self.assertEqual(totals["customer_overpayment_cents"], 0)
        self.assertEqual(totals["settled_customer_payments_cents"], 10_000)

        self.pay_settlement_bills()
        self.assertEqual(rs.summary(self.db)["available_cash_cents"], 52_000)

    # Trajectory 5 -------------------------------------------------------
    def test_05_customer_changes_agent_but_old_commission_stays_with_agent_a(self):
        self.make_case("guaranteed", agent_id="agent-a")
        changed = rs.change_agent(
            self.db, "edge.example", "customer-1", "agent-b", "mandate-2",
            "customer-signed-agent-b", 15,
        )
        self.assertEqual(changed["decision"], "agent_changed")

        current_mandate = one(
            self.db,
            "SELECT * FROM rs_mandates WHERE host='edge.example' AND status='active'",
        )
        self.assertEqual(current_mandate["agent_id"], "agent-b")
        self.assertEqual(
            one(self.db, "SELECT agent_id FROM rs_purchases WHERE purchase_id='case-1'")["agent_id"],
            "agent-a",
        )
        denied = rs.reassign_order_agent(self.db, "case-1", "agent-b")
        self.assertEqual(denied["decision"], "agent_reassignment_denied")

        self.first_payment_settled()
        self.two_acceptance_numbers()
        self.assertEqual(self.confirm_once()["decision"], "renewal_confirmed")

        bill = one(self.db, "SELECT * FROM rs_bills WHERE bill_id='bill-commission-case-1'")
        self.assertEqual(bill["party_id"], "agent-a")
        self.assertEqual(bill["account"], "agent_commission_payable:agent-a")
        self.assertEqual(
            rs.account_balance(self.db, "agent_commission_payable:agent-a"), 1_000)
        self.assertEqual(
            rs.account_balance(self.db, "agent_commission_payable:agent-b"), 0)

        self.pay_settlement_bills()
        self.assertEqual(
            rs.account_balance(self.db, "agent_commission_payable:agent-a"), 0)
        self.assertEqual(
            rs.account_balance(self.db, "agent_commission_payable:agent-b"), 0)
        self.assertEqual(rs.summary(self.db)["available_cash_cents"], 52_000)

    # Trajectory 6 -------------------------------------------------------
    def test_06_wrong_promise_is_immutable_and_compensated_from_deposit(self):
        self.db.execute(
            "INSERT INTO claims(host,holder,epoch,lease_until,challenge,status) "
            "VALUES('edge.example','customer-1',1,365,'dns-challenge','verified')"
        )
        self.make_case("guaranteed")
        self.first_payment_settled()
        self.promise_full_year()
        self.two_acceptance_numbers()

        breach = rs.record_promise_breach(
            self.db, "case-1", 400, "registry_receipt_late_and_interval_unproven",
        )
        self.assertEqual(breach["decision"], "promise_breached")
        self.assertEqual((breach["valid_from"], breach["valid_to"]), (365, 730))

        paid = rs.award_compensation(
            self.db, "compensation-1", "case-1", 3_000, 401,
            form="cash", pay_now=True, from_deposit=True,
        )
        self.assertEqual(paid["decision"], "compensation_paid")
        released = rs.release_guarantee_deposit(self.db, "case-1", 402)
        self.assertEqual(released["decision"], "deposit_released")
        self.assertEqual(released["released_cents"], 5_000)

        # The principal is also returned and the invoice is cancelled as a
        # separate accounting event; compensation is not a hidden refund.
        principal_refund = rs.refund_payment(
            self.db, "refund-principal-1", "payment-1", 403,
            "actual-principal-refund",
        )
        self.assertEqual(principal_refund["decision"], "refunded")
        cancelled = rs.cancel_customer_invoice(self.db, "case-1", 404)
        self.assertEqual(cancelled["decision"], "invoice_cancelled")

        promise = rs.entitlement(self.db, "case-1", "promised")
        self.assertEqual(promise["status"], "breached")
        self.assertEqual((promise["valid_from"], promise["valid_to"]), (365, 730))
        self.assertEqual(promise["breach_reason"],
                         "registry_receipt_late_and_interval_unproven")
        claim = one(self.db, "SELECT lease_until FROM claims WHERE host='edge.example'")
        self.assertEqual(claim["lease_until"], 365)

        compensation = one(self.db, "SELECT * FROM rs_compensations WHERE compensation_id=?",
                           ("compensation-1",))
        self.assertEqual(compensation["status"], "paid")
        self.assertEqual(compensation["amount_cents"], 3_000)

        totals = rs.summary(self.db)
        self.assertEqual(totals["compensation_expense_cents"], 3_000)
        self.assertEqual(totals["locked_deposit_cents"], 0)
        self.assertEqual(totals["available_cash_cents"], 47_000)
        self.assertEqual(totals["cash_total_cents"], 47_000)
        self.assertEqual(totals["customer_receivable_cents"], 0)
        self.assertEqual(rs.control_balances(self.db)["unearned_revenue"], 0)
        self.assertEqual(
            rs.settlement_distribution(self.db, "case-1")["customer_refunded_cents"],
            10_000,
        )
        self.assertEqual(totals["registered_entitlements"], 0)

    # Additional money-fact coverage ------------------------------------
    def test_settled_bank_return_is_distinct_from_platform_refund(self):
        self.make_case("confirmed_only")
        self.first_payment_settled()
        self.second_authorization_held()
        self.assertEqual(self.settle(2, 24)["overpayment_cents"], 10_000)

        returned = rs.return_payment(
            self.db, "bank-return-1", "payment-2", 26, "bank-return-ref-1",
        )
        self.assertEqual(returned["decision"], "returned")
        self.assertTrue(returned["bank_return"])
        self.assertFalse(returned["refund_posted"])
        self.assertEqual(rs.summary(self.db)["available_cash_cents"], 60_000)
        self.assertEqual(rs.summary(self.db)["customer_overpayment_cents"], 0)
        self.assertEqual(
            one(self.db,
                "SELECT COUNT(*) AS n FROM rs_payment_events WHERE event_type='return'")["n"],
            1,
        )
        self.assertEqual(
            one(self.db,
                "SELECT COUNT(*) AS n FROM rs_payment_events WHERE event_type='refund'")["n"],
            0,
        )

        rs.submit_to_registrar(
            self.db, "submission-1", "case-1", "ACCEPT-1", 30,
            registrar_order_id="registrar-order-1",
        )
        self.assertEqual(self.confirm_once()["decision"], "renewal_confirmed")
        self.pay_settlement_bills()
        self.assertEqual(rs.summary(self.db)["available_cash_cents"], 52_000)

    def test_conservative_fallback_refunds_duplicate_and_funds_migration_entry(self):
        self.make_case("confirmed_only")
        self.first_payment_settled()
        self.second_authorization_held()
        self.settle(2, 24)
        self.assertEqual(
            rs.refund_payment(self.db, "refund-2", "payment-2", 25, "rf-2")["decision"],
            "refunded",
        )

        backup = rs.secure_backup_entry(
            self.db, "backup-1", "case-1", "backup-edge.example", 26,
            valid_days=30, cost_cents=1_500, bear_now=False,
        )
        self.assertEqual(backup["decision"], "backup_entry_secured")
        self.assertEqual(rs.summary(self.db)["available_cash_cents"], 58_500)
        self.assertEqual(
            rs.summary(self.db)["platform_advance_outstanding_cents"], 1_500)

        borne = rs.bear_platform_advance(
            self.db, "adv-backup-backup-1", 27,
        )
        self.assertEqual(borne["decision"], "advance_borne_by_platform")
        totals = rs.summary(self.db)
        self.assertEqual(totals["platform_advance_outstanding_cents"], 0)
        self.assertEqual(totals["alternative_entry_expense_cents"], 1_500)
        self.assertEqual(totals["available_cash_cents"], 58_500)

        notice = one(self.db, "SELECT * FROM rs_notices WHERE notice_id='notice-backup-1'")
        self.assertEqual(notice["kind"], "migration")
        self.assertEqual(notice["old_host"], "edge.example")
        self.assertEqual(notice["backup_host"], "backup-edge.example")
        self.assertEqual(notice["status"], "issued")
        alternative = rs.entitlement(self.db, "case-1", "alternative")
        self.assertEqual(alternative["backup_host"], "backup-edge.example")
        self.assertEqual((alternative["valid_from"], alternative["valid_to"]), (26, 56))

        # A later authentic registry receipt can still upgrade the real domain;
        # the migration entry and notice remain traceable.
        rs.submit_to_registrar(
            self.db, "submission-1", "case-1", "ACCEPT-1", 30,
            registrar_order_id="registrar-order-1",
        )
        self.assertEqual(self.confirm_once()["decision"], "renewal_confirmed")
        self.pay_settlement_bills()
        self.assertEqual(rs.summary(self.db)["available_cash_cents"], 50_500)
        self.assertIsNotNone(rs.entitlement(self.db, "case-1", "alternative"))

    def test_command_dispatcher_is_idempotent_and_detects_conflict(self):
        command = {
            "request_id": "cmd-1", "op": "sign_mandate",
            "mandate_id": "mandate-cmd", "host": "cmd.example",
            "customer_id": "customer-cmd", "agent_id": "agent-a",
            "signature": "sig", "at": 1,
        }
        first = rs.run(self.db, command)
        second = rs.run(self.db, dict(command))
        self.assertEqual(first["decision"], "mandate_signed")
        self.assertEqual(second["decision"], "mandate_signed")

        conflict = rs.run(self.db, dict(command, signature="different"))
        self.assertEqual(conflict["decision"], "request_conflict")


if __name__ == "__main__":
    unittest.main()
