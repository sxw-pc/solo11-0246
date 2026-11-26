import json
import tempfile
import unittest
from pathlib import Path

import edgehandoff
from edgehandoff.store import connect, execute, replay, one, rows
from edgehandoff import sla_claim
from edgehandoff.sla_settlement import (
    merchant_balance, gl_balances, trace_payment, trace_request,
    CLAIMABLE, SEALED, PAID, REJECTED, RECOVERED, BOUNCED,
    K_LOSS, K_ADVANCE, K_PROVISION, K_PAY, K_REVERSE, K_REPAY,
    K_RECOVER, K_RECOVER_ADV, K_RECLASS, K_RELEASE,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'fixtures' / 'settlement_dispute.json'


class SlaSettlementTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'state.sqlite'
        self.db = connect(str(self.path))
        self.n = 0

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def act(self, op, **fields):
        self.n += 1
        fields.setdefault('request_id', f't-{self.n}')
        step = dict(op=op, **fields)
        return execute(self.db, 'settlement', step)

    def load_fixture(self):
        steps = json.loads(FIXTURE.read_text(encoding='utf-8'))
        return [execute(self.db, s['subsystem'], s) for s in steps]

    def item(self, case_id, order_no):
        return one(self.db, 'SELECT * FROM claim_items WHERE case_id=? AND order_no=?', (case_id, order_no))

    def entries(self, case_id, kind=None, order_no=None):
        sql = 'SELECT * FROM ledger_entries WHERE case_id=?'
        args = [case_id]
        if kind:
            sql += ' AND kind=?'; args.append(kind)
        if order_no:
            sql += ' AND order_no=?'; args.append(order_no)
        return rows(self.db, sql + ' ORDER BY at, entry_id', tuple(args))

    # ---------------------------------------------------------- basics

    def test_bad_samples_without_requests_pay_nothing(self):
        # The old draft pays per unhealthy sample; the new business must not.
        self.db.execute("INSERT INTO plans VALUES('p','h',1,'s','g','o','n',1,2,0,'active')")
        for i in range(3):
            self.db.execute("INSERT INTO samples VALUES(?,?,?,?,?)", (f's{i}', 'p', i, 100 + i, 0))
        self.assertEqual(sla_claim.draft(self.db, 'old-claim', 'p', 50)['amount'], 150)
        self.act('service_window', id='w', merchant='m', start_ts=90, end_ts=200)
        self.act('open_account', merchant='m', account_no='a1', at=95)
        self.act('open_case', case_id='c', merchant='m', window_id='w', plan_id='p', unit_cents=100, at=96)
        r = self.act('evaluate', case_id='c', at=97)
        self.assertEqual(r['decision'], 'evaluated')
        self.assertEqual(r['items'], [])
        r = self.act('settle', case_id='c', mode='proven_first', period='2026-11', at=98)
        self.assertEqual(r['merchant_received_cents'], 0)
        self.assertEqual(merchant_balance(self.db, 'm'), 0)
        self.assertEqual(self.entries('c'), [])

    def test_healthy_sample_still_compensates_lost_order(self):
        # healthy=1 sample cannot erase an accepted order that never completed
        self.db.execute("INSERT INTO plans VALUES('p','h',1,'s','g','o','n',1,2,1,'active')")
        self.db.execute("INSERT INTO samples VALUES('s0','p',1,120,1)")
        self.act('service_window', id='w', merchant='m', start_ts=100, end_ts=200)
        self.act('open_account', merchant='m', account_no='a1', at=95)
        self.act('ingress', merchant='m', order_no='L1', at=130)
        self.act('gateway_receipt', receipt_id='g1', ingress_request_id='t-3', accepted=True, at=130)
        self.act('open_case', case_id='c', merchant='m', window_id='w', plan_id='p', unit_cents=100, at=140)
        r = self.act('settle', case_id='c', mode='proven_first', period='2026-11', at=150)
        self.assertEqual(r['merchant_received_cents'], 100)
        self.assertEqual(self.item('c', 'L1')['status'], PAID)

    def test_retries_count_as_one_purchase_and_pay_once(self):
        self.act('service_window', id='w', merchant='m', start_ts=100, end_ts=200)
        self.act('open_account', merchant='m', account_no='a1', at=95)
        self.act('ingress', merchant='m', order_no='R1', at=110)
        self.act('gateway_receipt', receipt_id='g1', ingress_request_id='t-3', accepted=True, at=110)
        self.act('ingress', merchant='m', order_no='R1', at=112, retries_of='t-3')
        self.act('gateway_receipt', receipt_id='g2', ingress_request_id='t-5', accepted=True, at=112)
        self.act('ingress', merchant='m', order_no='R1', at=114, retries_of='t-3')
        self.act('gateway_receipt', receipt_id='g3', ingress_request_id='t-7', accepted=True, at=114)
        self.act('open_case', case_id='c', merchant='m', window_id='w', unit_cents=100, at=120)
        self.act('evaluate', case_id='c', at=121)
        self.assertEqual(len(rows(self.db, 'SELECT * FROM claim_items WHERE case_id=?', ('c',))), 1)
        item = self.item('c', 'R1')
        self.assertEqual(item['attempts'], 3)
        self.assertEqual(item['status'], CLAIMABLE)
        r = self.act('settle', case_id='c', mode='proven_first', period='2026-11', at=122)
        self.assertEqual(r['merchant_received_cents'], 100)
        self.assertEqual(len(self.entries('c', K_PAY)), 1)

    def test_request_outside_window_is_rejected(self):
        self.act('service_window', id='w', merchant='m', start_ts=100, end_ts=200)
        self.act('open_account', merchant='m', account_no='a1', at=95)
        self.act('ingress', merchant='m', order_no='X1', at=250)
        self.act('gateway_receipt', receipt_id='g1', ingress_request_id='t-3', accepted=True, at=250)
        self.act('open_case', case_id='c', merchant='m', window_id='w', unit_cents=100, at=260)
        self.act('evaluate', case_id='c', at=261)
        self.assertEqual(self.item('c', 'X1')['status'], REJECTED)
        self.assertEqual(self.item('c', 'X1')['basis'], 'not_accepted_in_window')

    # ---------------------------------------------------------- main dispute

    def test_fixture_classifies_six_complete_one_provable_one_sealed(self):
        results = self.load_fixture()
        self.assertEqual(results[-1]['decision'], 'evaluated')
        summary = results[-1]['summary']
        self.assertEqual(summary.get(CLAIMABLE), 1)   # O9: accepted, zero evidence of purchase
        self.assertEqual(summary.get(SEALED), 1)      # O8: self-claimed replay, no bank proof
        self.assertEqual(summary.get(REJECTED), 7)    # O1-O6 cashier success; O7 bank-cleared
        o7 = self.item('case-1', 'O7')
        self.assertEqual(o7['attempts'], 3)           # two retries collapse to one purchase
        self.assertEqual(o7['status'], REJECTED)
        self.assertEqual(o7['basis'], 'purchase_completed')
        o8 = self.item('case-1', 'O8')
        self.assertEqual(o8['status'], SEALED)
        self.assertEqual(self.item('case-1', 'O9')['status'], CLAIMABLE)

    def test_proven_first_pays_only_provable_loss_and_seals_dispute(self):
        self.load_fixture()
        r = self.act('settle', case_id='case-1', mode='proven_first', period='2026-11', at=180)
        self.assertEqual(r['decision'], 'settled_proven_first')
        self.assertEqual(r['merchant_received_cents'], 100)
        self.assertEqual(r['platform_receivable_cents'], 0)
        self.assertEqual(r['sealed_orders'], ['O8'])
        self.assertEqual(self.item('case-1', 'O9')['status'], PAID)
        self.assertEqual(self.item('case-1', 'O8')['status'], SEALED)
        # merchant balance only reflects the one payout; provision moves no merchant money
        self.assertEqual(merchant_balance(self.db, 'm-shop'), 100)
        gl = gl_balances(self.db, 'case-1')
        self.assertEqual(gl['sla_loss'], 100)
        self.assertEqual(gl['sealed_provision'], 100)
        self.assertEqual(gl['cash'], -100)
        # old sample-based draft figure (3 samples * rate) never appears
        self.assertNotIn(300, [e['amount_cents'] for e in self.entries('case-1')])

    def test_cap_advance_requires_signed_commitment_and_books_receivable(self):
        self.load_fixture()
        r = self.act('settle', case_id='case-1', mode='cap_advance', period='2026-11', at=180)
        self.assertEqual(r['decision'], 'commitment_required')
        self.act('preservation_commitment', commitment_id='cm-1', case_id='case-1',
                 cap_cents=200, signed_at=175)
        r = self.act('settle', case_id='case-1', mode='cap_advance', period='2026-11', at=180)
        self.assertEqual(r['decision'], 'settled_cap_advance')
        self.assertEqual(r['merchant_received_cents'], 200)   # O9 loss + O8 advance
        self.assertEqual(r['platform_receivable_cents'], 100)  # platform funds the dispute
        gl = gl_balances(self.db, 'case-1')
        self.assertEqual(gl['advance_receivable'], 100)
        self.assertEqual(gl['sla_loss'], 100)
        self.assertEqual(gl['cash'], -200)
        self.assertEqual(merchant_balance(self.db, 'm-shop'), 200)

    def test_two_settlement_modes_cannot_be_stacked(self):
        self.load_fixture()
        self.act('settle', case_id='case-1', mode='proven_first', period='2026-11', at=180)
        r = self.act('settle', case_id='case-1', mode='cap_advance', period='2026-11', at=181)
        self.assertEqual(r['decision'], 'mode_conflict')

    # ---------------------------------------------------------- evidence later

    def test_late_bank_denial_on_sealed_item_pays_won_dispute_next_month(self):
        self.load_fixture()
        self.act('settle', case_id='case-1', mode='proven_first', period='2026-11', at=180)
        # while the old backend's self-claim is unverified, reconciliation can't pay
        r = self.act('reconcile', case_id='case-1', order_no='O8', period='2026-12', at=400)
        self.assertEqual(r['effects'][0]['effect'], 'still_sealed')
        # next month the bank rules explicitly: no money was ever received for O8
        self.act('bank_clearing', merchant='m-shop', clearing_no='clr-deny-8', order_no='O8', paid=False, bounced=False, at=401)
        r = self.act('reconcile', case_id='case-1', order_no='O8', period='2026-12', at=402)
        self.assertEqual(r['effects'][0]['effect'], 'dispute_won_paid')
        self.assertEqual(r['effects'][0]['amount_cents'], 100)
        self.assertEqual(self.item('case-1', 'O8')['status'], PAID)
        # provision released, new loss + payout in December; November invoice untouched
        self.assertEqual(len(self.entries('case-1', K_RELEASE, 'O8')), 1)
        dec = [e for e in self.entries('case-1', order_no='O8') if e['period'] == '2026-12']
        self.assertTrue(any(e['kind'] == K_LOSS for e in dec))
        self.assertTrue(any(e['kind'] == K_PAY for e in dec))
        self.assertTrue(all(e['period'] != '2026-11' or e['kind'] == K_PROVISION
                            for e in self.entries('case-1', order_no='O8')))
        # dispute -> claimable transition is explicit: bank denial resolved it
        self.assertEqual(self.item('case-1', 'O8')['basis'], 'bank_denied_self_claimed_replay')

    def test_clearing_number_arrives_only_correcting_entries_are_created(self):
        # O8 was advanced in cap mode; then a real bank clearing receipt proves
        # the purchase actually completed -> over-payment recovered, no rewrite.
        self.load_fixture()
        self.act('preservation_commitment', commitment_id='cm-1', case_id='case-1',
                 cap_cents=200, signed_at=175)
        self.act('settle', case_id='case-1', mode='cap_advance', period='2026-11', at=180)
        before = rows(self.db, 'SELECT * FROM ledger_entries WHERE case_id=? ORDER BY entry_id', ('case-1',))
        invoice_before = one(self.db, "SELECT * FROM invoices WHERE invoice_no='inv-case-1-2026-11'")
        # the previously self-claimed replay now gets a real bank clearing number
        self.act('bank_clearing', merchant='m-shop', clearing_no='clr-8', order_no='O8', paid=True, bounced=False, at=390)
        r = self.act('reconcile', case_id='case-1', order_no='O8', period='2026-12', at=400)
        self.assertEqual(r['effects'][0]['effect'], 'recovered')
        after = rows(self.db, 'SELECT * FROM ledger_entries WHERE case_id=? ORDER BY at, entry_id', ('case-1',))
        # every old entry survives byte-identical; only new correcting entries appended
        before_ids = {e['entry_id'] for e in before}
        preserved = [e for e in after if e['entry_id'] in before_ids]
        self.assertEqual(len(preserved), len(before))
        self.assertEqual({tuple(sorted(e.items())) for e in before},
                         {tuple(sorted(e.items())) for e in preserved})
        self.assertEqual(invoice_before, one(self.db, "SELECT * FROM invoices WHERE invoice_no='inv-case-1-2026-11'"))
        correction = [e for e in after if e['entry_id'] not in before_ids]
        self.assertTrue(all(e['period'] == '2026-12' for e in correction))
        self.assertTrue(any(e['kind'] == K_RECOVER_ADV for e in correction))
        # merchant balance corrected down by 100; GL advance cleared, recovery claim opened
        self.assertEqual(merchant_balance(self.db, 'm-shop'), 100)
        gl = gl_balances(self.db, 'case-1')
        self.assertEqual(gl.get('advance_receivable', 0), 0)
        self.assertEqual(gl['recovery_receivable'], 100)
        self.assertEqual(gl['sla_loss'], 100)          # only O9 was a real loss
        self.assertEqual(self.item('case-1', 'O8')['status'], RECOVERED)
        # a credit-note invoice row exists and points at the case, original stays
        cn = rows(self.db, "SELECT * FROM invoices WHERE invoice_no LIKE 'cn-case-1-2026-12-%'")
        self.assertEqual(len(cn), 1)
        self.assertEqual(cn[0]['amount_cents'], -100)

    def test_bank_denial_turns_advance_into_real_loss_without_new_cash(self):
        self.load_fixture()
        self.act('preservation_commitment', commitment_id='cm-1', case_id='case-1',
                 cap_cents=200, signed_at=175)
        self.act('settle', case_id='case-1', mode='cap_advance', period='2026-11', at=180)
        # bank explicitly rules O8 unpaid: the advance becomes a realized SLA loss
        self.act('bank_clearing', merchant='m-shop', clearing_no='clr-deny-8', order_no='O8', paid=False, bounced=False, at=390)
        cash_before = gl_balances(self.db, 'case-1')['cash']
        r = self.act('reconcile', case_id='case-1', order_no='O8', period='2026-12', at=400)
        self.assertEqual(r['effects'][0]['effect'], 'advance_realized')
        gl = gl_balances(self.db, 'case-1')
        self.assertEqual(gl['cash'], cash_before)          # no new cash moved
        self.assertEqual(gl.get('advance_receivable', 0), 0)  # receivable cleared to zero...
        self.assertEqual(gl['sla_loss'], 200)              # ...and realized as loss
        self.assertEqual(len(self.entries('case-1', K_RECLASS, 'O8')), 1)

    def test_month_end_clear_recovers_advance_and_closes_case(self):
        self.load_fixture()
        self.act('preservation_commitment', commitment_id='cm-1', case_id='case-1',
                 cap_cents=200, signed_at=175)
        self.act('settle', case_id='case-1', mode='cap_advance', period='2026-11', at=180)
        # bank proves O8 (the advanced item) was actually completed
        self.act('bank_clearing', merchant='m-shop', clearing_no='clr-8', order_no='O8', paid=True, bounced=False, at=395)
        r = self.act('month_end_clear', case_id='case-1', period='2026-12', at=500)
        self.assertEqual(r['decision'], 'cleared')
        self.assertEqual(r['recovered_cents'], 100)
        self.assertEqual(one(self.db, "SELECT status FROM sla_cases WHERE case_id='case-1'")['status'], 'cleared')
        self.assertEqual(merchant_balance(self.db, 'm-shop'), 100)  # 200 paid, 100 recovered

    # ---------------------------------------------------------- banking

    def test_bank_bounce_then_repayment_to_new_account(self):
        self.load_fixture()
        r = self.act('settle', case_id='case-1', mode='proven_first', period='2026-11', at=180)
        payout = rows(self.db, "SELECT * FROM bank_payments WHERE direction='credit' AND status='sent'")[0]
        r = self.act('payout_bounced', bank_ref=payout['bank_ref'], reversal_id='rev-1', at=200)
        self.assertEqual(r['decision'], 'bounced')
        order_no = one(self.db, 'SELECT order_no FROM ledger_entries WHERE entry_id=?',
                       (payout['entry_id'],))['order_no']
        self.assertEqual(self.item('case-1', order_no)['status'], BOUNCED)
        self.assertEqual(len(self.entries('case-1', K_REVERSE)), 1)
        self.assertEqual(merchant_balance(self.db, 'm-shop'), 0)
        # customer closes old account and names a new one before re-payment
        self.act('change_account', change_id='chg-1', merchant='m-shop',
                 new_account='acct-2', reason='customer_reaccount', at=210)
        r = self.act('repay', bank_ref=payout['bank_ref'], new_bank_ref='bk-repay-1',
                     repay_entry_id='repay-1', period='2026-11', at=220)
        self.assertEqual(r['decision'], 'repaid')
        self.assertEqual(r['account_no'], 'acct-2')
        self.assertEqual(self.item('case-1', order_no)['status'], PAID)
        # first pay, reversal and re-payment are three separately traceable books
        kinds = [e['kind'] for e in self.entries('case-1', order_no=order_no)]
        self.assertIn(K_PAY, kinds); self.assertIn(K_REVERSE, kinds); self.assertIn(K_REPAY, kinds)
        self.assertEqual(merchant_balance(self.db, 'm-shop'), 100)
        # the re-payment ref alone reconstructs the entire chain back to the request
        trace = trace_payment(self.db, 'bk-repay-1')
        self.assertEqual({p['bank_ref'] for p in trace['all_bank_payments']},
                         {payout['bank_ref'], 'bk-repay-1'})
        chain_kinds = [e['kind'] for e in trace['ledger_chain']]
        self.assertEqual(chain_kinds, [K_LOSS, K_PAY, K_REVERSE, K_REPAY])
        self.assertEqual(trace['orders'][order_no]['claim_item']['status'], PAID)

    def test_repay_requires_a_bounce(self):
        self.load_fixture()
        self.act('settle', case_id='case-1', mode='proven_first', period='2026-11', at=180)
        payout = rows(self.db, "SELECT * FROM bank_payments WHERE direction='credit' AND status='sent'")[0]
        r = self.act('repay', bank_ref=payout['bank_ref'], new_bank_ref='bk-x',
                     repay_entry_id='repay-x', period='2026-11', at=220)
        self.assertEqual(r['decision'], 'bounce_required')

    def test_payout_blocked_when_account_closed(self):
        self.load_fixture()
        self.act('close_account', change_id='close-1', merchant='m-shop', at=175)
        r = self.act('settle', case_id='case-1', mode='proven_first', period='2026-11', at=180)
        self.assertEqual(r['decision'], 'payout_account_unavailable')
        # account change keeps an original pointer from old to new account
        self.act('open_account', merchant='m2', account_no='a', at=1)
        self.act('change_account', change_id='chg-x', merchant='m2', new_account='b', reason='rename', at=2)
        chg = one(self.db, "SELECT * FROM account_changes WHERE change_id='chg-x'")
        self.assertEqual((chg['old_account'], chg['new_account']), ('a', 'b'))

    def test_refund_turns_paid_claim_into_recovery(self):
        self.act('service_window', id='w', merchant='m', start_ts=100, end_ts=200)
        self.act('open_account', merchant='m', account_no='a1', at=95)
        self.act('ingress', merchant='m', order_no='F1', at=120)
        self.act('gateway_receipt', receipt_id='g1', ingress_request_id='t-3', accepted=True, at=120)
        self.act('open_case', case_id='c', merchant='m', window_id='w', unit_cents=100, at=130)
        self.act('settle', case_id='c', mode='proven_first', period='2026-11', at=140)
        self.act('refund', merchant='m', refund_id='rf1', order_no='F1', at=300)
        r = self.act('reconcile', case_id='c', order_no='F1', period='2026-12', at=310)
        self.assertEqual(r['effects'][0]['effect'], 'recovered')
        self.assertEqual(self.item('c', 'F1')['status'], RECOVERED)
        self.assertEqual(merchant_balance(self.db, 'm'), 0)

    # ---------------------------------------------------------- traceability

    def test_payment_traces_back_to_request_purchase_and_bank(self):
        self.load_fixture()
        self.act('settle', case_id='case-1', mode='proven_first', period='2026-11', at=180)
        payout = rows(self.db, "SELECT * FROM bank_payments WHERE direction='credit'")[0]
        trace = trace_payment(self.db, payout['bank_ref'])
        self.assertIsNotNone(trace)
        self.assertEqual(trace['bank_payment']['bank_ref'], payout['bank_ref'])
        order = trace['orders']['O9']
        self.assertEqual(len(order['requests']), 1)
        self.assertEqual(order['gateway_receipts'][0]['accepted'], 1)
        self.assertEqual(order['cashier'], [])          # never confirmed -> the loss
        self.assertEqual(order['bank_clearing'], [])    # no bank evidence either
        self.assertEqual(order['claim_item']['status'], PAID)

    def test_request_trace_follows_retry_chain(self):
        self.load_fixture()
        t = trace_request(self.db, 'e-r7b')
        self.assertEqual(t['canonical'], 'e-r7a')
        self.assertEqual(len(t['retry_chain']), 3)
        self.assertEqual({r['request_id'] for r in t['retry_chain']},
                         {'e-r7a', 'e-r7b', 'e-r7c'})
        self.assertEqual(len(t['gateway_receipts']), 3)

    # ---------------------------------------------------------- replay

    def test_full_history_replays_byte_identical(self):
        self.load_fixture()
        self.act('preservation_commitment', commitment_id='cm-1', case_id='case-1',
                 cap_cents=200, signed_at=175)
        self.act('settle', case_id='case-1', mode='cap_advance', period='2026-11', at=180)
        payout = rows(self.db, "SELECT * FROM bank_payments WHERE direction='credit' AND status='sent'")[0]
        self.act('payout_bounced', bank_ref=payout['bank_ref'], reversal_id='rev-1', at=200)
        self.act('change_account', change_id='chg-1', merchant='m-shop',
                 new_account='acct-2', reason='reaccount', at=210)
        self.act('repay', bank_ref=payout['bank_ref'], new_bank_ref='bk-repay-1',
                 repay_entry_id='repay-1', period='2026-11', at=220)
        self.act('bank_clearing', merchant='m-shop', clearing_no='clr-8', order_no='O8', paid=True, bounced=False, at=390)
        self.act('reconcile', case_id='case-1', order_no='O8', period='2026-12', at=400)
        report = replay(str(self.path))
        self.assertTrue(report['verified'], report['divergence'])

    def test_idempotent_replay_of_same_request(self):
        self.load_fixture()
        step = {'request_id': 'e-r1', 'op': 'ingress', 'merchant': 'm-shop',
                'order_no': 'O1', 'at': 110}
        first = execute(self.db, 'settlement', dict(step))
        second = execute(self.db, 'settlement', dict(step))
        self.assertEqual(first, second)

    # -------------------------------------------------- edge replayability

    def test_duplicate_gateway_receipt_is_rejected(self):
        self.act('service_window', id='w', merchant='m', start_ts=100, end_ts=200)
        self.act('open_account', merchant='m', account_no='a1', at=95)
        self.act('ingress', merchant='m', order_no='D1', at=120)
        rid = self.n
        self.assertEqual(self.act('gateway_receipt', receipt_id='q1',
                                  ingress_request_id=f't-{rid}', accepted=True, at=120)['decision'],
                         'receipt_recorded')
        # same receipt identity twice (gateway duplicate echo) must not double-accept
        self.assertEqual(self.act('gateway_receipt', receipt_id='q1',
                                  ingress_request_id=f't-{rid}', accepted=True, at=121)['decision'],
                         'receipt_conflict')
        # a receipt pointing at an unknown request is rejected too
        self.assertEqual(self.act('gateway_receipt', receipt_id='q2',
                                  ingress_request_id='nope', accepted=True, at=122)['decision'],
                         'unknown_request')

    def test_rejected_claim_overturned_by_late_evidence_pays_as_correction(self):
        self.act('service_window', id='w', merchant='m', start_ts=100, end_ts=200)
        self.act('open_account', merchant='m', account_no='a1', at=95)
        self.act('ingress', merchant='m', order_no='V1', at=120)
        rid = self.n
        self.act('gateway_receipt', receipt_id='q1', ingress_request_id=f't-{rid}', accepted=True, at=120)
        # a cashier success initially makes the item a completed, rejected claim
        self.act('cashier_confirmation', merchant='m', confirmation_id='cc-v1', order_no='V1', success=True, at=130)
        self.act('open_case', case_id='c', merchant='m', window_id='w', unit_cents=100, at=140)
        self.act('evaluate', case_id='c', at=141)
        self.assertEqual(self.item('c', 'V1')['status'], REJECTED)
        # bill review disproves the cashier confirmation (bounced settlement),
        # represented by an explicit bank ruling that no money was received
        self.act('bank_clearing', merchant='m', clearing_no='clr-v1', order_no='V1', paid=False, bounced=True, at=300)
        r = self.act('reconcile', case_id='c', order_no='V1', period='2026-12', at=310)
        self.assertEqual(r['effects'][0]['effect'], 'rejection_overturned_paid')
        self.assertEqual(self.item('c', 'V1')['status'], PAID)
        self.assertEqual(merchant_balance(self.db, 'm'), 100)
        # the corrective payout lands in December, never rewrites November's books
        dec = self.entries('c', order_no='V1')
        self.assertTrue(all(e['period'] == '2026-12' for e in dec))

    def test_cutover_rollback_replays_alongside_settlement(self):
        # full cross-subsystem history: ownership/certificate/cutover incl. a
        # rollback, then an SLA case over the same plan — all byte-identical
        for name in ('ownership_normal', 'certificate_normal', 'cutover_normal'):
            for s in json.loads((ROOT / 'fixtures' / f'{name}.json').read_text(encoding='utf-8')):
                execute(self.db, s.get('subsystem', name.split('_')[0]), s)
        # more unhealthy samples while the plan is still active (event-sourced)
        execute(self.db, 'cutover', {'request_id': 'x-s2', 'op': 'sample', 'id': 'bad-2',
                                     'plan': 'cut-1', 'stage': 2, 'at': 20, 'healthy': False})
        self.assertEqual(execute(self.db, 'cutover', {
            'request_id': 'x-rollback', 'op': 'rollback', 'id': 'rollback-x',
            'plan': 'cut-1', 'at': 40})['decision'], 'restored')
        # the SLA case cites the rolled-back plan; samples failed during it but
        # no customer request exists, so no money is paid despite bad samples
        self.act('service_window', id='w', merchant='team-b', start_ts=40, end_ts=90)
        self.act('open_account', merchant='team-b', account_no='a1', at=41)
        self.act('open_case', case_id='c-roll', merchant='team-b', window_id='w',
                 plan_id='cut-1', unit_cents=100, at=60)
        r = self.act('settle', case_id='c-roll', mode='proven_first', period='2026-11', at=70)
        self.assertEqual(r['merchant_received_cents'], 0)
        report = replay(str(self.path))
        self.assertTrue(report['verified'], report['divergence'])

    # -------------------------------------------------- review regressions

    def _one_order_case(self, merchant='m', window='w', case='c', order='D1'):
        self.act('service_window', id=window, merchant=merchant, start_ts=100, end_ts=200)
        self.act('open_account', merchant=merchant, account_no='a1', at=95)
        self.act('ingress', merchant=merchant, order_no=order, at=120)
        rid = self.n
        self.act('gateway_receipt', receipt_id=f'q-{order}', ingress_request_id=f't-{rid}',
                 accepted=True, at=120)
        self.act('open_case', case_id=case, merchant=merchant, window_id=window,
                 unit_cents=100, at=140)

    def test_H1_overlapping_cases_cannot_pay_one_purchase_twice(self):
        self.act('service_window', id='w1', merchant='m', start_ts=100, end_ts=200)
        self.act('service_window', id='w2', merchant='m', start_ts=150, end_ts=300)
        self.act('open_account', merchant='m', account_no='a1', at=95)
        self.act('ingress', merchant='m', order_no='DUP', at=160)
        rid = self.n
        self.act('gateway_receipt', receipt_id='qD', ingress_request_id=f't-{rid}', accepted=True, at=160)
        self.act('open_case', case_id='c1', merchant='m', window_id='w1', unit_cents=100, at=170)
        # the second overlapping case is refused at open time
        r = self.act('open_case', case_id='c2', merchant='m', window_id='w2', unit_cents=100, at=171)
        self.assertEqual(r['decision'], 'overlapping_case')

    def test_H2_proven_first_recovery_credits_loss_and_debits_receivable(self):
        self._one_order_case(order='F1')
        self.act('settle', case_id='c', mode='proven_first', period='2026-11', at=150)
        self.act('refund', merchant='m', refund_id='rf1', order_no='F1', at=300)
        self.act('reconcile', case_id='c', order_no='F1', period='2026-12', at=310)
        gl = gl_balances(self.db, 'c')
        # the original 100 loss is fully reversed; the owed money is a receivable
        self.assertEqual(gl.get('sla_loss', 0), 0)
        self.assertEqual(gl['recovery_receivable'], 100)
        self.assertEqual(gl['cash'], -100)  # cash left once, not netted away

    def test_H3_recovered_order_cannot_be_revived_by_bounce_and_repay(self):
        self._one_order_case(order='F3')
        self.act('settle', case_id='c', mode='proven_first', period='2026-11', at=150)
        payout = rows(self.db, "SELECT * FROM bank_payments WHERE status='sent'")[0]
        self.act('refund', merchant='m', refund_id='rf3', order_no='F3', at=160)
        self.act('reconcile', case_id='c', order_no='F3', period='2026-11', at=170)
        # a late bounce on an already recovered payout is refused
        self.assertEqual(self.act('payout_bounced', bank_ref=payout['bank_ref'],
                                  reversal_id='rv', at=180)['decision'], 'item_already_recovered')

    def test_H3_repay_rechecks_eligibility_after_refund(self):
        self._one_order_case(order='F4')
        self.act('settle', case_id='c', mode='proven_first', period='2026-11', at=150)
        payout = rows(self.db, "SELECT * FROM bank_payments WHERE status='sent'")[0]
        self.act('payout_bounced', bank_ref=payout['bank_ref'], reversal_id='rv2', at=160)
        # while bounced, evidence shows the order was actually refunded
        self.act('refund', merchant='m', refund_id='rf4', order_no='F4', at=170)
        r = self.act('repay', bank_ref=payout['bank_ref'], new_bank_ref='bk-x',
                     repay_entry_id='re-x', period='2026-11', at=180)
        self.assertEqual(r['decision'], 'repay_ineligible')
        self.assertEqual(merchant_balance(self.db, 'm'), 0)

    def test_H4_repeated_reconcile_is_idempotent(self):
        self.load_fixture()
        self.act('preservation_commitment', commitment_id='cm-1', case_id='case-1',
                 cap_cents=200, signed_at=175)
        self.act('settle', case_id='case-1', mode='cap_advance', period='2026-11', at=180)
        self.act('bank_clearing', merchant='m-shop', clearing_no='clr-deny-8',
                 order_no='O8', paid=False, bounced=False, at=390)
        first = self.act('reconcile', case_id='case-1', order_no='O8', period='2026-12', at=400)
        entries_after_first = rows(self.db, 'SELECT entry_id FROM ledger_entries')
        # resubmitting a ruling with a new event id must not crash or double-post
        second = self.act('reconcile', case_id='case-1', order_no='O8', period='2026-12', at=401)
        self.assertEqual(first['effects'][0]['effect'], 'advance_realized')
        self.assertEqual(second['effects'][0]['effect'], 'basis_updated')
        self.assertEqual(rows(self.db, 'SELECT entry_id FROM ledger_entries'), entries_after_first)

    def test_M1_two_corrections_in_one_period_keep_separate_invoices(self):
        # two sealed items both win in December: two payouts, two invoices
        self.act('service_window', id='w', merchant='m', start_ts=100, end_ts=200)
        self.act('open_account', merchant='m', account_no='a1', at=95)
        for o in ('S1', 'S2'):
            self.act('ingress', merchant='m', order_no=o, at=120)
            rid = self.n
            self.act('gateway_receipt', receipt_id=f'q-{o}', ingress_request_id=f't-{rid}',
                     accepted=True, at=120)
            self.act('backend_replay', merchant='m', replay_id=f'rp-{o}', order_no=o,
                     success=True, at=130)
        self.act('open_case', case_id='c', merchant='m', window_id='w', unit_cents=100, at=140)
        self.act('settle', case_id='c', mode='proven_first', period='2026-11', at=150)
        for o in ('S1', 'S2'):
            self.act('bank_clearing', merchant='m', clearing_no=f'd-{o}', order_no=o,
                     paid=False, bounced=False, at=300)
            self.act('reconcile', case_id='c', order_no=o, period='2026-12', at=310)
        dec_invoices = rows(self.db, "SELECT * FROM invoices WHERE period='2026-12'")
        self.assertEqual(len(dec_invoices), 2)
        self.assertEqual(sum(i['amount_cents'] for i in dec_invoices), 200)
        self.assertEqual(merchant_balance(self.db, 'm'), 200)

    def test_M2_evidence_is_scoped_per_merchant(self):
        for m in ('mA', 'mB'):
            self.act('service_window', id=f'w-{m}', merchant=m, start_ts=100, end_ts=200)
            self.act('open_account', merchant=m, account_no=f'ac-{m}', at=95)
            self.act('ingress', merchant=m, order_no='Z', at=110)
            rid = self.n
            self.act('gateway_receipt', receipt_id=f'q-{m}', ingress_request_id=f't-{rid}',
                     accepted=True, at=110)
        # mA's order Z is paid at the cashier; mB's identical order number is not
        self.act('cashier_confirmation', merchant='mA', confirmation_id='cc1',
                 order_no='Z', success=True, at=120)
        self.act('open_case', case_id='cA', merchant='mA', window_id='w-mA', unit_cents=100, at=140)
        self.act('open_case', case_id='cB', merchant='mB', window_id='w-mB', unit_cents=100, at=141)
        rA = self.act('settle', case_id='cA', mode='proven_first', period='2026-11', at=150)
        rB = self.act('settle', case_id='cB', mode='proven_first', period='2026-11', at=151)
        self.assertEqual(rA['merchant_received_cents'], 0)    # mA's Z completed
        self.assertEqual(rB['merchant_received_cents'], 100)  # mB's Z still lost

    def test_M2b_replay_cannot_quote_another_orders_clearing(self):
        self._one_order_case(order='Q')
        self.act('bank_clearing', merchant='m', clearing_no='clr-other', order_no='OTHER',
                 paid=True, bounced=False, at=120)
        r = self.act('backend_replay', merchant='m', replay_id='rpq', order_no='Q',
                     success=True, clearing_no='clr-other', at=130)
        self.assertEqual(r['decision'], 'clearing_reference_mismatch')

    def test_M3_recovered_item_is_terminal(self):
        self._one_order_case(order='R1')
        self.act('settle', case_id='c', mode='proven_first', period='2026-11', at=150)
        self.act('refund', merchant='m', refund_id='rfR', order_no='R1', at=160)
        self.act('reconcile', case_id='c', order_no='R1', period='2026-11', at=170)
        self.assertEqual(self.item('c', 'R1')['status'], RECOVERED)
        # any later reconcile on the same order is a no-op, status stays recovered
        r = self.act('reconcile', case_id='c', order_no='R1', period='2026-12', at=300)
        self.assertEqual(r['effects'][0]['effect'], 'already_recovered')
        self.assertEqual(self.item('c', 'R1')['status'], RECOVERED)

    def test_L2_nested_retry_chain_counts_all_attempts(self):
        self.act('service_window', id='w', merchant='m', start_ts=100, end_ts=200)
        self.act('open_account', merchant='m', account_no='a1', at=95)
        self.act('ingress', merchant='m', order_no='N1', at=110)
        root = self.n
        self.act('gateway_receipt', receipt_id='q-n1', ingress_request_id=f't-{root}',
                 accepted=True, at=110)
        self.act('ingress', merchant='m', order_no='N1', at=112, retries_of=f't-{root}')
        mid = self.n
        self.act('gateway_receipt', receipt_id='q-n2', ingress_request_id=f't-{mid}',
                 accepted=True, at=112)
        # a retry of a retry: nested chain must still collapse to one purchase
        self.act('ingress', merchant='m', order_no='N1', at=114, retries_of=f't-{mid}')
        leaf = self.n
        self.act('gateway_receipt', receipt_id='q-n3', ingress_request_id=f't-{leaf}',
                 accepted=True, at=114)
        self.act('open_case', case_id='c', merchant='m', window_id='w', unit_cents=100, at=120)
        self.act('evaluate', case_id='c', at=121)
        item = self.item('c', 'N1')
        self.assertEqual(item['attempts'], 3)
        self.assertEqual(item['status'], CLAIMABLE)
        t = trace_request(self.db, f't-{mid}')
        self.assertEqual(t['canonical'], f't-{root}')
        self.assertEqual(len(t['retry_chain']), 3)


if __name__ == '__main__':
    unittest.main()
