"""Service compensation (SLA) settlement.

The old ``sla_claim.draft`` multiplied unhealthy *samples* by a per-minute
rate.  Samples only record plan/stage/timestamp/healthy — they carry no
customer request and no payment fact, so a single bad sample was enough to
print money.  This module rebuilds the business from the claim originals:

* ingress request (the customer's checkout attempt, with retry chain),
* gateway acceptance receipt (only an *accepted* request inside the agreed
  service window can be compensated),
* cashier confirmation, customer order, old-backend replay log and bank
  clearing receipt (the facts deciding whether the purchase was ever paid).

Money only moves through immutable double-sided ledger entries; later
evidence never rewrites an old invoice, it posts a correcting entry that
points back to the original payment, request and invoice.
"""
from .store import one, rows

# Item lifecycle
DISPUTED = 'disputed'      # accepted in window, purchase truth unknown
CLAIMABLE = 'claimable'    # proven lost purchase: accepted, never paid
SEALED = 'sealed'          # parked pending bank reconciliation
PAID = 'paid'              # compensation already sent to the merchant
REJECTED = 'rejected'      # accepted but purchase completed / refunded / outside window
RECOVERED = 'recovered'    # over-paid money recovered via correction
BOUNCED = 'bounced'        # payout bank transfer returned, re-payment pending

# Ledger entry kinds (already-paid credit / pending claim / re-payment stay
# in separate books — the three amounts must never be netted silently)
K_LOSS = 'claim_loss'             # proven-loss compensation (P&L expense)
K_ADVANCE = 'advance_receivable'  # cap-mode money advanced against a sealed item
K_PROVISION = 'sealed_provision'  # no cash moved: provision for a sealed item
K_PAY = 'payout'                  # actual cash leaving the platform's bank
K_REVERSE = 'payout_reversal'     # bank bounce: cash comes back
K_REPAY = 'repayment'             # re-payment after a bounce (separate from first pay)
K_RECOVER = 'overpayment_recovery'
K_RECOVER_RECV = 'recovery_receivable'  # money owed back on a proven-loss payout
K_RECOVER_ADV = 'advance_recovery'      # reversal of an advance receivable
K_RECLASS = 'advance_reclass'     # advance -> realized loss (no new cash)
K_RELEASE = 'provision_release'
K_INVOICE_CORRECT = 'invoice_correction'

GL = {
    K_LOSS: 'sla_loss',
    K_ADVANCE: 'advance_receivable',
    K_PROVISION: 'sealed_provision',
    K_PAY: 'cash',
    K_REVERSE: 'cash',
    K_REPAY: 'cash',
    K_RECOVER: 'sla_loss',
    K_RECOVER_RECV: 'recovery_receivable',
    K_RECOVER_ADV: 'recovery_receivable',
    K_RECLASS: 'advance_receivable',
    K_RELEASE: 'sealed_provision',
    K_INVOICE_CORRECT: 'sla_loss',
}


# ---------------------------------------------------------------- evidence

def _window(db, x):
    w = one(db, 'SELECT * FROM service_windows WHERE id=?', (x['window_id'],))
    if not w or w['merchant'] != x['merchant']:
        return None
    return w


def _account(db, merchant):
    return one(db, "SELECT * FROM merchant_accounts WHERE merchant=? AND status='open'", (merchant,))


def _entry(db, **f):
    db.execute(
        'INSERT INTO ledger_entries VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (f['entry_id'], f['case_id'], f.get('request_id'), f.get('order_no'), f['kind'],
         f['amount'], f['merchant_delta'], GL[f['kind']], f['gl_delta'], f['period'],
         f.get('origin_entry'), f.get('origin_invoice'), f.get('bank_ref'), f['at']))


def _completed(merchant, order_no, db):
    """True once money actually changed hands for this purchase.

    Evidence is always scoped to the merchant: the same order number used by
    another merchant can never decide this claim.  An explicit bank ruling is
    final: a ``paid=0`` clearing overturns a stale cashier success (e.g. a
    settlement that later bounced).
    """
    if _bank_denied(merchant, order_no, db):
        return False
    if one(db, 'SELECT 1 FROM cashier_confirmations WHERE merchant=? AND order_no=? AND success=1',
           (merchant, order_no)):
        return True
    if one(db, 'SELECT 1 FROM bank_clearing WHERE merchant=? AND order_no=? AND paid=1',
           (merchant, order_no)):
        return True
    if one(db, 'SELECT 1 FROM purchase_replays WHERE merchant=? AND order_no=? AND success=1 '
           'AND clearing_no IS NOT NULL', (merchant, order_no)):
        return True
    return False


def _bank_denied(merchant, order_no, db):
    """The bank has explicitly ruled on this order: no money was received."""
    return one(db, 'SELECT 1 FROM bank_clearing WHERE merchant=? AND order_no=? AND paid=0',
               (merchant, order_no)) is not None


def _refunded(merchant, order_no, db):
    return one(db, 'SELECT 1 FROM refunds WHERE merchant=? AND order_no=?',
               (merchant, order_no)) is not None


def _canonical(db, request_id):
    """Walk the retry chain to its original request (handles nested retries)."""
    seen = set()
    current = request_id
    while True:
        if current in seen:
            return current
        seen.add(current)
        row = one(db, 'SELECT request_id, retries_of FROM ingress_requests WHERE request_id=?', (current,))
        if not row or not row['retries_of']:
            return current
        current = row['retries_of']


def _classify(db, case, canonical, order_no, at):
    """Decide one deduplicated request: rejected / claimable / sealed."""
    merchant = case['merchant']
    if _refunded(merchant, order_no, db):
        return REJECTED, 'order_refunded'
    accepted = rows(db,
                    'SELECT gr.* FROM gateway_receipts gr JOIN ingress_requests ir ON gr.request_id=ir.request_id '
                    'WHERE ir.merchant=? AND ir.order_no=?', (merchant, order_no))
    w = one(db, 'SELECT * FROM service_windows WHERE id=?', (case['window_id'],))
    in_window = any(r['accepted'] and w['start_ts'] <= r['at'] <= w['end_ts'] for r in accepted)
    if not in_window:
        return REJECTED, 'not_accepted_in_window'
    if _completed(merchant, order_no, db):
        return REJECTED, 'purchase_completed'
    self_only = one(db, 'SELECT 1 FROM purchase_replays WHERE merchant=? AND order_no=? AND success=1 '
                        'AND clearing_no IS NULL', (merchant, order_no))
    if self_only and not _bank_denied(merchant, order_no, db):
        # old backend claims success without bank proof: park, never pay
        return SEALED, 'unverified_backend_replay'
    if self_only:
        return CLAIMABLE, 'bank_denied_self_claimed_replay'
    return CLAIMABLE, 'accepted_purchase_missing'


def _evaluate(db, x):
    case = one(db, 'SELECT * FROM sla_cases WHERE case_id=?', (x['case_id'],))
    if not case:
        return {'decision': 'unknown_case'}
    reqs = rows(db, 'SELECT * FROM ingress_requests WHERE merchant=? ORDER BY at, request_id',
                (case['merchant'],))
    groups = {}
    for r in reqs:
        canonical = _canonical(db, r['request_id'])
        groups.setdefault(canonical, []).append(r)
    decided = []
    for canonical, chain in groups.items():
        order_no = chain[0]['order_no']
        item_id = f"{case['case_id']}:{order_no}"
        old = one(db, 'SELECT * FROM claim_items WHERE id=?', (item_id,))
        if old and old['status'] in (PAID, RECOVERED, BOUNCED):
            # money already moved: only reconciliation entries may change it
            decided.append({'id': item_id, 'order_no': order_no, 'status': old['status'], 'frozen': True})
            continue
        # H1: a single purchase can never be paid by two cases — if another
        # open/settled case already pays this merchant's order, it is rejected here
        other = one(db, 'SELECT ci.id FROM claim_items ci JOIN sla_cases sc ON ci.case_id=sc.case_id '
                        "WHERE sc.merchant=? AND ci.order_no=? AND ci.case_id<>? AND ci.status IN ('paid','bounced')",
                    (case['merchant'], order_no, x['case_id']))
        if other:
            status, basis = REJECTED, 'compensated_in_other_case'
        else:
            status, basis = _classify(db, case, canonical, order_no, x['at'])
        amount = case['unit_cents'] if status in (CLAIMABLE, SEALED) else 0
        db.execute(
            'INSERT INTO claim_items VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
            'attempts=excluded.attempts,accepted_in_window=excluded.accepted_in_window,'
            'status=excluded.status,basis=excluded.basis,amount_cents=excluded.amount_cents,updated_at=excluded.updated_at',
            (item_id, case['case_id'], order_no, canonical, len(chain),
             int(status != REJECTED or basis != 'not_accepted_in_window'), status, basis, amount, x['at']))
        decided.append({'id': item_id, 'order_no': order_no, 'status': status, 'amount_cents': amount})
    summary = {}
    for d in decided:
        summary[d['status']] = summary.get(d['status'], 0) + 1
    return {'decision': 'evaluated', 'case_id': case['case_id'], 'items': decided, 'summary': summary}


def _open_invoice(db, case, period, amount, at, mode, order_no=None):
    # M1: corrective invoices are per order so two corrections in one period
    # can never overwrite each other; the period invoice aggregates the case
    suffix = f"-{order_no}" if order_no else ""
    invoice_no = f"inv-{case['case_id']}-{period}{suffix}"
    old = one(db, 'SELECT * FROM invoices WHERE invoice_no=?', (invoice_no,))
    if not old:
        db.execute('INSERT INTO invoices VALUES(?,?,?,?,?,?)',
                   (invoice_no, case['case_id'], period, amount, mode, at))
    return invoice_no


# ---------------------------------------------------------------- run

def run(db, x):
    op = x['op']

    if op == 'service_window':
        if one(db, 'SELECT 1 FROM service_windows WHERE id=?', (x['id'],)):
            return {'decision': 'window_conflict'}
        if x['end_ts'] <= x['start_ts']:
            return {'decision': 'invalid_window'}
        db.execute('INSERT INTO service_windows VALUES(?,?,?,?)',
                   (x['id'], x['merchant'], x['start_ts'], x['end_ts']))
        return {'decision': 'window_registered'}

    if op == 'open_account':
        if one(db, 'SELECT 1 FROM merchant_accounts WHERE merchant=?', (x['merchant'],)):
            return {'decision': 'account_conflict'}
        db.execute('INSERT INTO merchant_accounts VALUES(?,?,?,?)',
                   (x['merchant'], x['account_no'], 'open', x['at']))
        return {'decision': 'account_opened'}

    if op == 'close_account':
        acc = one(db, 'SELECT * FROM merchant_accounts WHERE merchant=?', (x['merchant'],))
        if not acc or acc['status'] != 'open':
            return {'decision': 'account_not_open'}
        db.execute('UPDATE merchant_accounts SET status=? WHERE merchant=?', ('closed', x['merchant']))
        db.execute('INSERT INTO account_changes VALUES(?,?,?,?,?,?)',
                   (x['change_id'], x['merchant'], acc['account_no'], None, 'customer_closure', x['at']))
        return {'decision': 'account_closed'}

    if op == 'change_account':
        acc = one(db, 'SELECT * FROM merchant_accounts WHERE merchant=?', (x['merchant'],))
        if not acc or acc['status'] != 'open':
            return {'decision': 'account_not_open'}
        if one(db, 'SELECT 1 FROM account_changes WHERE change_id=?', (x['change_id'],)):
            return {'decision': 'change_conflict'}
        db.execute('INSERT INTO account_changes VALUES(?,?,?,?,?,?)',
                   (x['change_id'], x['merchant'], acc['account_no'], x['new_account'], x['reason'], x['at']))
        db.execute('UPDATE merchant_accounts SET account_no=? WHERE merchant=?',
                   (x['new_account'], x['merchant']))
        return {'decision': 'account_changed'}

    if op == 'ingress':
        if one(db, 'SELECT 1 FROM ingress_requests WHERE request_id=?', (x['request_id'],)):
            return {'decision': 'request_conflict'}
        parent = x.get('retries_of')
        if parent:
            root = one(db, 'SELECT * FROM ingress_requests WHERE request_id=?', (parent,))
            if not root or root['order_no'] != x['order_no'] or root['merchant'] != x['merchant']:
                return {'decision': 'retry_chain_broken'}
        db.execute('INSERT INTO ingress_requests VALUES(?,?,?,?,?)',
                   (x['request_id'], x['merchant'], x['order_no'], x['at'], parent))
        return {'decision': 'ingress_recorded',
                'canonical': parent or x['request_id']}

    if op == 'gateway_receipt':
        if one(db, 'SELECT 1 FROM gateway_receipts WHERE receipt_id=?', (x['receipt_id'],)):
            return {'decision': 'receipt_conflict'}
        req = one(db, 'SELECT * FROM ingress_requests WHERE request_id=?', (x['ingress_request_id'],))
        if not req:
            return {'decision': 'unknown_request'}
        db.execute('INSERT INTO gateway_receipts VALUES(?,?,?,?)',
                   (x['receipt_id'], x['ingress_request_id'], int(x['accepted']), x['at']))
        return {'decision': 'receipt_recorded', 'accepted': int(x['accepted'])}

    if op == 'cashier_confirmation':
        if one(db, 'SELECT 1 FROM cashier_confirmations WHERE confirmation_id=?', (x['confirmation_id'],)):
            return {'decision': 'confirmation_conflict'}
        db.execute('INSERT INTO cashier_confirmations VALUES(?,?,?,?,?)',
                   (x['confirmation_id'], x['merchant'], x['order_no'], int(x['success']), x['at']))
        return {'decision': 'confirmation_recorded'}

    if op == 'backend_replay':
        if one(db, 'SELECT 1 FROM purchase_replays WHERE replay_id=?', (x['replay_id'],)):
            return {'decision': 'replay_conflict'}
        if x.get('clearing_no'):
            # the quoted bank receipt must exist AND belong to this same order
            clr = one(db, 'SELECT * FROM bank_clearing WHERE clearing_no=?', (x['clearing_no'],))
            if not clr:
                return {'decision': 'clearing_reference_missing'}
            if clr['order_no'] != x['order_no'] or clr['merchant'] != x['merchant']:
                return {'decision': 'clearing_reference_mismatch'}
        db.execute('INSERT INTO purchase_replays VALUES(?,?,?,?,?,?)',
                   (x['replay_id'], x['merchant'], x['order_no'], int(x['success']),
                    x.get('clearing_no'), x['at']))
        return {'decision': 'replay_recorded'}

    if op == 'bank_clearing':
        if one(db, 'SELECT 1 FROM bank_clearing WHERE clearing_no=?', (x['clearing_no'],)):
            return {'decision': 'clearing_conflict'}
        db.execute('INSERT INTO bank_clearing VALUES(?,?,?,?,?,?)',
                   (x['clearing_no'], x['merchant'], x['order_no'], int(x['paid']),
                    int(x.get('bounced', 0)), x['at']))
        return {'decision': 'clearing_recorded'}

    if op == 'refund':
        if one(db, 'SELECT 1 FROM refunds WHERE refund_id=?', (x['refund_id'],)):
            return {'decision': 'refund_conflict'}
        db.execute('INSERT INTO refunds VALUES(?,?,?,?)',
                   (x['refund_id'], x['merchant'], x['order_no'], x['at']))
        return {'decision': 'refund_recorded'}

    if op == 'open_case':
        if not _window(db, x):
            return {'decision': 'unknown_window'}
        if x['unit_cents'] < 0:
            return {'decision': 'invalid_rate'}
        if one(db, 'SELECT 1 FROM sla_cases WHERE case_id=?', (x['case_id'],)):
            return {'decision': 'case_conflict'}
        # H1: overlapping service windows for the same merchant would let one
        # purchase be paid twice — the second case is refused up front
        win = _window(db, x)
        overlap = one(db,
                      'SELECT sc.case_id FROM sla_cases sc JOIN service_windows sw ON sc.window_id=sw.id '
                      "WHERE sc.merchant=? AND sc.status IN ('open','settled') AND sw.id<>? "
                      'AND sw.start_ts<=? AND sw.end_ts>=?',
                      (x['merchant'], x['window_id'], win['end_ts'], win['start_ts']))
        if overlap:
            return {'decision': 'overlapping_case', 'case_id': overlap['case_id']}
        db.execute('INSERT INTO sla_cases VALUES(?,?,?,?,?,?,?,?)',
                   (x['case_id'], x['merchant'], x['window_id'], x.get('plan_id'),
                    x['unit_cents'], None, 'open', x['at']))
        return {'decision': 'case_opened'}

    if op == 'preservation_commitment':
        case = one(db, 'SELECT * FROM sla_cases WHERE case_id=?', (x['case_id'],))
        if not case:
            return {'decision': 'unknown_case'}
        if one(db, 'SELECT 1 FROM preservation_commitments WHERE commitment_id=?', (x['commitment_id'],)):
            return {'decision': 'commitment_conflict'}
        db.execute('INSERT INTO preservation_commitments VALUES(?,?,?,?)',
                   (x['commitment_id'], x['case_id'], x['cap_cents'], x['signed_at']))
        return {'decision': 'commitment_recorded', 'cap_cents': x['cap_cents']}

    if op == 'evaluate':
        return _evaluate(db, x)

    if op == 'settle':
        return _settle(db, x)

    if op == 'payout_bounced':
        return _bounce(db, x)

    if op == 'repay':
        return _repay(db, x)

    if op == 'reconcile':
        return _reconcile(db, x)

    if op == 'month_end_clear':
        return _month_end(db, x)

    raise ValueError(op)


# ---------------------------------------------------------------- settlement

def _settle(db, x):
    case = one(db, 'SELECT * FROM sla_cases WHERE case_id=?', (x['case_id'],))
    if not case:
        return {'decision': 'unknown_case'}
    if case['mode'] and case['mode'] != x['mode']:
        # the two payout timelines are mutually exclusive — never stack them
        return {'decision': 'mode_conflict', 'existing_mode': case['mode']}
    if case['status'] in ('settled', 'cleared'):
        return {'decision': 'already_settled'}
    acc = _account(db, case['merchant'])
    if not acc:
        return {'decision': 'payout_account_unavailable'}
    evaluation = _evaluate(db, {'case_id': x['case_id'], 'at': x['at']})
    items = rows(db, 'SELECT * FROM claim_items WHERE case_id=? ORDER BY id', (x['case_id'],))
    claimable = [i for i in items if i['status'] == CLAIMABLE]
    sealed = [i for i in items if i['status'] == SEALED]
    invoice_no = _open_invoice(db, case, x['period'], 0, x['at'], x['mode'])
    seq = 0

    def next_id(kind):
        nonlocal seq
        seq += 1
        # H4: include the event request id so resubmitted/correction events
        # never regenerate an existing entry id, while replay stays deterministic
        return f"{x['case_id']}-{kind}-{seq:03d}-{x['request_id']}"

    if x['mode'] == 'proven_first':
        # contract path A: pay only what is provably lost today; disputed
        # items are sealed with a provision, no cash advances, platform bears
        # no funding cost on the dispute.
        paid_total = 0
        for it in claimable:
            loss_id = next_id('loss')
            pay_id = next_id('pay')
            _entry(db, entry_id=loss_id, case_id=case['case_id'], request_id=it['canonical_request'],
                   order_no=it['order_no'], kind=K_LOSS, amount=it['amount_cents'],
                   merchant_delta=0, gl_delta=it['amount_cents'], period=x['period'], at=x['at'])
            _entry(db, entry_id=pay_id, case_id=case['case_id'], request_id=it['canonical_request'],
                   order_no=it['order_no'], kind=K_PAY, amount=it['amount_cents'],
                   merchant_delta=it['amount_cents'], gl_delta=-it['amount_cents'],
                   period=x['period'], origin_invoice=invoice_no, at=x['at'])
            db.execute('INSERT INTO bank_payments VALUES(?,?,?,?,?,?,?)',
                       (f"bk-{pay_id}", pay_id, acc['account_no'], it['amount_cents'], 'credit', 'sent', x['at']))
            db.execute('UPDATE claim_items SET status=?,updated_at=? WHERE id=?', (PAID, x['at'], it['id']))
            paid_total += it['amount_cents']
        for it in sealed:
            prov_id = next_id('prov')
            _entry(db, entry_id=prov_id, case_id=case['case_id'], request_id=it['canonical_request'],
                   order_no=it['order_no'], kind=K_PROVISION, amount=case['unit_cents'],
                   merchant_delta=0, gl_delta=case['unit_cents'], period=x['period'], at=x['at'])
            db.execute('UPDATE claim_items SET status=?,updated_at=? WHERE id=?', (SEALED, x['at'], it['id']))
        db.execute("UPDATE invoices SET amount_cents=? WHERE invoice_no=?", (paid_total, invoice_no))
        db.execute("UPDATE sla_cases SET mode=?,status='settled' WHERE case_id=?",
                   ('proven_first', x['case_id']))
        return {'decision': 'settled_proven_first', 'case_id': x['case_id'],
                'invoice_no': invoice_no, 'merchant_received_cents': paid_total,
                'platform_receivable_cents': 0,
                'sealed_orders': [i['order_no'] for i in sealed],
                'funded_by': 'platform_pnl_for_proven_loss_only'}

    if x['mode'] == 'cap_advance':
        # contract path B: only after the merchant signs the preservation
        # commitment, the platform advances up to the cap.  Cash on sealed
        # items is an advance (platform receivable, merchant owes return at
        # next-month clearing) — the funding occupation is the platform's.
        commitment = one(db, 'SELECT * FROM preservation_commitments WHERE case_id=? ORDER BY signed_at DESC LIMIT 1',
                         (x['case_id'],))
        if not commitment:
            return {'decision': 'commitment_required'}
        cap = commitment['cap_cents']
        proven_total = sum(i['amount_cents'] for i in claimable)
        advance_budget = max(0, cap - proven_total)
        advanced, advance_orders = 0, []
        for it in claimable:
            loss_id, pay_id = next_id('loss'), next_id('pay')
            _entry(db, entry_id=loss_id, case_id=case['case_id'], request_id=it['canonical_request'],
                   order_no=it['order_no'], kind=K_LOSS, amount=it['amount_cents'],
                   merchant_delta=0, gl_delta=it['amount_cents'], period=x['period'], at=x['at'])
            _entry(db, entry_id=pay_id, case_id=case['case_id'], request_id=it['canonical_request'],
                   order_no=it['order_no'], kind=K_PAY, amount=it['amount_cents'],
                   merchant_delta=it['amount_cents'], gl_delta=-it['amount_cents'],
                   period=x['period'], origin_invoice=invoice_no, at=x['at'])
            db.execute('INSERT INTO bank_payments VALUES(?,?,?,?,?,?,?)',
                       (f"bk-{pay_id}", pay_id, acc['account_no'], it['amount_cents'], 'credit', 'sent', x['at']))
            db.execute('UPDATE claim_items SET status=?,updated_at=? WHERE id=?', (PAID, x['at'], it['id']))
        for it in sealed:
            if advanced >= advance_budget:
                break
            adv_id, pay_id = next_id('adv'), next_id('pay')
            _entry(db, entry_id=adv_id, case_id=case['case_id'], request_id=it['canonical_request'],
                   order_no=it['order_no'], kind=K_ADVANCE, amount=case['unit_cents'],
                   merchant_delta=0, gl_delta=case['unit_cents'], period=x['period'], at=x['at'])
            _entry(db, entry_id=pay_id, case_id=case['case_id'], request_id=it['canonical_request'],
                   order_no=it['order_no'], kind=K_PAY, amount=case['unit_cents'],
                   merchant_delta=case['unit_cents'], gl_delta=-case['unit_cents'],
                   period=x['period'], origin_invoice=invoice_no, at=x['at'])
            db.execute('INSERT INTO bank_payments VALUES(?,?,?,?,?,?,?)',
                       (f"bk-{pay_id}", pay_id, acc['account_no'], case['unit_cents'], 'credit', 'sent', x['at']))
            db.execute('UPDATE claim_items SET status=?,updated_at=? WHERE id=?', (PAID, x['at'], it['id']))
            advanced += case['unit_cents']
            advance_orders.append(it['order_no'])
        db.execute("UPDATE invoices SET amount_cents=? WHERE invoice_no=?",
                   (proven_total + advanced, invoice_no))
        db.execute("UPDATE sla_cases SET mode=?,status='settled' WHERE case_id=?",
                   ('cap_advance', x['case_id']))
        return {'decision': 'settled_cap_advance', 'case_id': x['case_id'],
                'invoice_no': invoice_no, 'merchant_received_cents': proven_total + advanced,
                'proven_loss_cents': proven_total, 'platform_receivable_cents': advanced,
                'advanced_orders': advance_orders,
                'funded_by': 'platform_cash_advance_under_signed_commitment'}

    return {'decision': 'unknown_mode'}


def _bounce(db, x):
    """A bank payout is returned: reverse cash, item awaits re-payment."""
    pay = one(db, "SELECT * FROM bank_payments WHERE bank_ref=? AND direction='credit'", (x['bank_ref'],))
    if not pay:
        return {'decision': 'unknown_payment'}
    if pay['status'] != 'sent':
        return {'decision': 'payment_not_outstanding'}
    entry = one(db, 'SELECT * FROM ledger_entries WHERE entry_id=?', (pay['entry_id'],))
    item = one(db, 'SELECT * FROM claim_items WHERE case_id=? AND order_no=?',
               (entry['case_id'], entry['order_no']))
    # H3: a payout on an order already recovered/rejected must not be revived
    if item and item['status'] == RECOVERED:
        return {'decision': 'item_already_recovered'}
    db.execute("UPDATE bank_payments SET status='bounced' WHERE bank_ref=?", (x['bank_ref'],))
    db.execute('INSERT INTO ledger_entries VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (x['reversal_id'], entry['case_id'], entry['request_id'], entry['order_no'], K_REVERSE,
                pay['amount_cents'], -pay['amount_cents'], GL[K_REVERSE], pay['amount_cents'],
                entry['period'], entry['entry_id'], entry['origin_invoice'], x['bank_ref'], x['at']))
    db.execute('UPDATE claim_items SET status=?,updated_at=? WHERE case_id=? AND order_no=?',
               (BOUNCED, x['at'], entry['case_id'], entry['order_no']))
    return {'decision': 'bounced', 'bank_ref': x['bank_ref'], 'amount_cents': pay['amount_cents']}


def _repay(db, x):
    """Re-pay a bounced transfer (possibly to a new account); booked apart."""
    pay = one(db, "SELECT * FROM bank_payments WHERE bank_ref=? AND direction='credit'", (x['bank_ref'],))
    if not pay or pay['status'] != 'bounced':
        return {'decision': 'bounce_required'}
    entry = one(db, 'SELECT * FROM ledger_entries WHERE entry_id=?', (pay['entry_id'],))
    item = one(db, 'SELECT * FROM claim_items WHERE case_id=? AND order_no=?',
               (entry['case_id'], entry['order_no']))
    if not item or item['status'] != BOUNCED:
        return {'decision': 'item_not_bounced'}
    case = one(db, 'SELECT * FROM sla_cases WHERE case_id=?', (entry['case_id'],))
    # H3: re-check the evidence now.  A refund, cashier/bank proof of payment
    # or a bank denial overturn means the order no longer qualifies for cash.
    status, basis = _classify(db, case, item['canonical_request'], entry['order_no'], x['at'])
    if status == REJECTED:
        db.execute('UPDATE claim_items SET status=?,basis=?,updated_at=? WHERE id=?',
                   (REJECTED, basis, x['at'], item['id']))
        return {'decision': 'repay_ineligible', 'basis': basis}
    acc = _account(db, case['merchant'])
    if not acc:
        return {'decision': 'payout_account_unavailable'}
    if one(db, 'SELECT 1 FROM bank_payments WHERE bank_ref=?', (x['new_bank_ref'],)):
        return {'decision': 'bank_ref_conflict'}
    db.execute('INSERT INTO ledger_entries VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (x['repay_entry_id'], entry['case_id'], entry['request_id'], entry['order_no'], K_REPAY,
                pay['amount_cents'], pay['amount_cents'], GL[K_REPAY], -pay['amount_cents'],
                x['period'], entry['entry_id'], entry['origin_invoice'], x['new_bank_ref'], x['at']))
    db.execute('INSERT INTO bank_payments VALUES(?,?,?,?,?,?,?)',
               (x['new_bank_ref'], x['repay_entry_id'], acc['account_no'], pay['amount_cents'],
                'credit', 'sent', x['at']))
    db.execute('UPDATE claim_items SET status=?,updated_at=? WHERE id=?', (PAID, x['at'], item['id']))
    return {'decision': 'repaid', 'bank_ref': x['new_bank_ref'],
            'amount_cents': pay['amount_cents'], 'account_no': acc['account_no']}


def _reconcile(db, x):
    """New evidence (clearing number / replay) arrives after settlement.

    Old invoices and old entries stay untouched; every correction is a new
    entry in the current period pointing at the original.  The effect of a
    reconcile event is deterministic and idempotent per (case, order,
    resulting status): re-running the same ruling posts nothing twice.
    """
    case = one(db, 'SELECT * FROM sla_cases WHERE case_id=?', (x['case_id'],))
    if not case:
        return {'decision': 'unknown_case'}
    order_no = x['order_no']
    item = one(db, 'SELECT * FROM claim_items WHERE case_id=? AND order_no=?', (x['case_id'], order_no))
    if not item:
        return {'decision': 'unknown_item'}
    status, basis = _classify(db, case, item['canonical_request'], order_no, x['at'])
    out = []
    seq = 0

    def cid(kind):
        nonlocal seq
        seq += 1
        # H4: event-scoped ids keep replay deterministic and prevent
        # collisions when several reconcile events correct the same order
        return f"{x['case_id']}-{kind}-cor-{order_no}-{seq:02d}-{x['request_id']}"

    def post(kind, amount, merchant_delta, gl_delta, origin=None, invoice=None, bank_ref=None):
        _entry(db, entry_id=cid(kind), case_id=x['case_id'], request_id=item['canonical_request'],
               order_no=order_no, kind=kind, amount=amount, merchant_delta=merchant_delta,
               gl_delta=gl_delta, period=x['period'], origin_entry=origin,
               origin_invoice=invoice, bank_ref=bank_ref, at=x['at'])

    # M3: a recovered item is terminal — no later evidence may reopen it
    if item['status'] == RECOVERED:
        return {'decision': 'reconciled', 'case_id': x['case_id'],
                'effects': [{'order_no': order_no, 'effect': 'already_recovered'}]}

    if item['status'] == PAID:
        origin = one(db, "SELECT * FROM ledger_entries WHERE case_id=? AND order_no=? AND kind=? ORDER BY at LIMIT 1",
                     (x['case_id'], order_no, K_PAY))
        invoice_no = origin['origin_invoice']
        if status == REJECTED:
            # merchant actually got the goods/money: recover the over-payment.
            adv = one(db, "SELECT entry_id FROM ledger_entries WHERE case_id=? AND order_no=? AND kind=?",
                      (x['case_id'], order_no, K_ADVANCE))
            if adv:
                # cap mode: reverse the advance receivable and open a recovery
                # claim on the merchant; no SLA loss was ever recognized
                post(K_RECLASS, item['amount_cents'], 0, -item['amount_cents'], origin=adv['entry_id'],
                     invoice=invoice_no)
                post(K_RECOVER_ADV, item['amount_cents'], -item['amount_cents'], item['amount_cents'],
                     origin=origin['entry_id'], invoice=invoice_no)
            else:
                # proven-first mode: reverse the recognized loss (credit sla_loss)
                # and debit a recovery receivable for the money owed back
                post(K_RECOVER, item['amount_cents'], 0, -item['amount_cents'],
                     origin=origin['entry_id'], invoice=invoice_no)
                post(K_RECOVER_RECV, item['amount_cents'], -item['amount_cents'], item['amount_cents'],
                     origin=origin['entry_id'], invoice=invoice_no)
            db.execute('INSERT INTO invoices VALUES(?,?,?,?,?,?)',
                       (f"cn-{x['case_id']}-{x['period']}-{order_no}", x['case_id'], x['period'],
                        -item['amount_cents'], case['mode'], x['at']))
            db.execute('UPDATE claim_items SET status=?,basis=?,updated_at=? WHERE id=?',
                       (RECOVERED, basis, x['at'], item['id']))
            out.append({'order_no': order_no, 'effect': 'recovered', 'amount_cents': item['amount_cents']})
        elif status == CLAIMABLE and case['mode'] == 'cap_advance':
            # advance converted into a real loss: no new cash, reclass only.
            # H4: once a reclass already exists for this order, repeat rulings
            # are a no-op so the same evidence can never post twice.
            already = one(db, "SELECT 1 FROM ledger_entries WHERE case_id=? AND order_no=? AND kind=?",
                          (x['case_id'], order_no, K_RECLASS))
            adv = one(db, "SELECT * FROM ledger_entries WHERE case_id=? AND order_no=? AND kind=?",
                      (x['case_id'], order_no, K_ADVANCE))
            if adv and not already:
                post(K_LOSS, item['amount_cents'], 0, item['amount_cents'])
                post(K_RECLASS, item['amount_cents'], 0, -item['amount_cents'], origin=adv['entry_id'])
                db.execute('UPDATE claim_items SET basis=?,updated_at=? WHERE id=?',
                           (basis, x['at'], item['id']))
                out.append({'order_no': order_no, 'effect': 'advance_realized',
                            'amount_cents': item['amount_cents']})
            else:
                db.execute('UPDATE claim_items SET basis=?,updated_at=? WHERE id=?',
                           (basis, x['at'], item['id']))
                out.append({'order_no': order_no, 'effect': 'basis_updated'})
        else:
            db.execute('UPDATE claim_items SET basis=?,updated_at=? WHERE id=?', (basis, x['at'], item['id']))
            out.append({'order_no': order_no, 'effect': 'basis_updated'})
    elif item['status'] == SEALED:
        origin = one(db, "SELECT * FROM ledger_entries WHERE case_id=? AND order_no=? AND kind=? ORDER BY at LIMIT 1",
                     (x['case_id'], order_no, K_PROVISION))
        if status == CLAIMABLE:
            # dispute resolved in merchant's favour: release provision, pay now
            if origin:
                post(K_RELEASE, item['amount_cents'] or case['unit_cents'], 0,
                     -(item['amount_cents'] or case['unit_cents']), origin=origin['entry_id'])
            amount = case['unit_cents']
            invoice_no = _open_invoice(db, case, x['period'], 0, x['at'], case['mode'], order_no)
            post(K_LOSS, amount, 0, amount, invoice=invoice_no)
            acc = _account(db, case['merchant'])
            if not acc:
                return {'decision': 'payout_account_unavailable'}
            pay_id = cid('pay')
            _entry(db, entry_id=pay_id, case_id=x['case_id'], request_id=item['canonical_request'],
                   order_no=order_no, kind=K_PAY, amount=amount, merchant_delta=amount,
                   gl_delta=-amount, period=x['period'], origin_invoice=invoice_no, at=x['at'])
            db.execute('INSERT INTO bank_payments VALUES(?,?,?,?,?,?,?)',
                       (f"bk-{pay_id}", pay_id, acc['account_no'], amount, 'credit', 'sent', x['at']))
            db.execute("UPDATE invoices SET amount_cents=? WHERE invoice_no=?", (amount, invoice_no))
            db.execute('UPDATE claim_items SET status=?,basis=?,amount_cents=?,updated_at=? WHERE id=?',
                       (PAID, basis, amount, x['at'], item['id']))
            out.append({'order_no': order_no, 'effect': 'dispute_won_paid', 'amount_cents': amount})
        elif status == REJECTED:
            if origin:
                post(K_RELEASE, case['unit_cents'], 0, -case['unit_cents'], origin=origin['entry_id'])
            db.execute('UPDATE claim_items SET status=?,basis=?,updated_at=? WHERE id=?',
                       (REJECTED, basis, x['at'], item['id']))
            out.append({'order_no': order_no, 'effect': 'dispute_lost_rejected'})
        else:
            db.execute('UPDATE claim_items SET basis=?,updated_at=? WHERE id=?', (basis, x['at'], item['id']))
            out.append({'order_no': order_no, 'effect': 'still_sealed'})
    else:
        if status == CLAIMABLE and item['status'] == REJECTED:
            # the earlier rejection is overturned: pay as a new-period
            # correction that cites the original rejected claim
            invoice_no = _open_invoice(db, case, x['period'], 0, x['at'], case['mode'], order_no)
            post(K_LOSS, case['unit_cents'], 0, case['unit_cents'], invoice=invoice_no)
            acc = _account(db, case['merchant'])
            if not acc:
                return {'decision': 'payout_account_unavailable'}
            pay_id = cid('pay')
            _entry(db, entry_id=pay_id, case_id=x['case_id'], request_id=item['canonical_request'],
                   order_no=order_no, kind=K_PAY, amount=case['unit_cents'],
                   merchant_delta=case['unit_cents'], gl_delta=-case['unit_cents'],
                   period=x['period'], origin_invoice=invoice_no, at=x['at'])
            db.execute('INSERT INTO bank_payments VALUES(?,?,?,?,?,?,?)',
                       (f"bk-{pay_id}", pay_id, acc['account_no'], case['unit_cents'],
                        'credit', 'sent', x['at']))
            db.execute("UPDATE invoices SET amount_cents=? WHERE invoice_no=?",
                       (case['unit_cents'], invoice_no))
            db.execute('UPDATE claim_items SET status=?,basis=?,amount_cents=?,updated_at=? WHERE id=?',
                       (PAID, basis, case['unit_cents'], x['at'], item['id']))
            out.append({'order_no': order_no, 'effect': 'rejection_overturned_paid',
                        'amount_cents': case['unit_cents']})
        elif status == SEALED and item['status'] == REJECTED:
            # L1: a later seal must still carry a provision so a future
            # release has something to reverse
            post(K_PROVISION, case['unit_cents'], 0, case['unit_cents'])
            db.execute('UPDATE claim_items SET status=?,basis=?,amount_cents=?,updated_at=? WHERE id=?',
                       (SEALED, basis, case['unit_cents'], x['at'], item['id']))
            out.append({'order_no': order_no, 'effect': 'reclassified', 'status': SEALED})
        elif status != item['status']:
            db.execute('UPDATE claim_items SET status=?,basis=?,updated_at=? WHERE id=?',
                       (status, basis, x['at'], item['id']))
            out.append({'order_no': order_no, 'effect': 'reclassified', 'status': status})
        else:
            db.execute('UPDATE claim_items SET basis=?,updated_at=? WHERE id=?', (basis, x['at'], item['id']))
            out.append({'order_no': order_no, 'effect': 'basis_updated'})
    return {'decision': 'reconciled', 'case_id': x['case_id'], 'effects': out}


def _month_end(db, x):
    """Next-month clearing under cap_advance: settle every advance."""
    case = one(db, 'SELECT * FROM sla_cases WHERE case_id=?', (x['case_id'],))
    if not case:
        return {'decision': 'unknown_case'}
    if case['mode'] != 'cap_advance':
        return {'decision': 'clear_requires_cap_advance'}
    if case['status'] == 'cleared':
        return {'decision': 'already_cleared'}
    recovered, realized, still_open = 0, 0, []
    for it in rows(db, 'SELECT * FROM claim_items WHERE case_id=? ORDER BY id', (x['case_id'],)):
        has_advance = one(db, 'SELECT 1 FROM ledger_entries WHERE case_id=? AND order_no=? AND kind=?',
                          (x['case_id'], it['order_no'], K_ADVANCE))
        if not has_advance:
            continue
        status, basis = _classify(db, case, it['canonical_request'], it['order_no'], x['at'])
        if status == REJECTED and it['status'] == PAID:
            _reconcile(db, {'request_id': f"{x['request_id']}-{it['order_no']}",
                            'case_id': x['case_id'], 'order_no': it['order_no'],
                            'period': x['period'], 'at': x['at']})
            recovered += it['amount_cents']
        elif status == CLAIMABLE and it['status'] == PAID:
            _reconcile(db, {'request_id': f"{x['request_id']}-{it['order_no']}",
                            'case_id': x['case_id'], 'order_no': it['order_no'],
                            'period': x['period'], 'at': x['at']})
            realized += it['amount_cents']
        else:
            still_open.append(it['order_no'])
    db.execute("UPDATE sla_cases SET status='cleared' WHERE case_id=?", (x['case_id'],))
    return {'decision': 'cleared', 'case_id': x['case_id'],
            'recovered_cents': recovered, 'realized_loss_cents': realized,
            'still_disputed': still_open}


# ---------------------------------------------------------------- queries

def merchant_balance(db, merchant):
    row = db.execute('SELECT COALESCE(SUM(merchant_delta),0) AS b FROM ledger_entries WHERE case_id IN '
                     '(SELECT case_id FROM sla_cases WHERE merchant=?)', (merchant,)).fetchone()
    return row['b']


def gl_balances(db, case_id):
    out = {}
    for r in db.execute('SELECT gl_account, SUM(gl_delta) AS b FROM ledger_entries WHERE case_id=? GROUP BY gl_account',
                        (case_id,)):
        out[r['gl_account']] = r['b']
    return out


def trace_payment(db, bank_ref):
    """From any bank payment back to request, purchase result and ledger path.

    Follows the whole order-level chain: original payout, bank reversal and
    re-payment are all returned, not only the entry the given ref names.
    """
    pay = one(db, 'SELECT * FROM bank_payments WHERE bank_ref=?', (bank_ref,))
    if not pay:
        return None
    anchor = one(db, 'SELECT * FROM ledger_entries WHERE entry_id=?', (pay['entry_id'],))
    if not anchor:
        return None
    case_id, order_no = anchor['case_id'], anchor['order_no']
    chain = rows(db, 'SELECT * FROM ledger_entries WHERE case_id=? AND order_no=? ORDER BY at, entry_id',
                 (case_id, order_no))
    order_nos = [order_no] if order_no else sorted({e['order_no'] for e in chain if e['order_no']})
    result = {
        'bank_payment': pay,
        'all_bank_payments': rows(db, 'SELECT * FROM bank_payments WHERE entry_id IN '
                                  '(SELECT entry_id FROM ledger_entries WHERE case_id=? AND order_no=?) '
                                  'ORDER BY at, bank_ref', (case_id, order_no)),
        'ledger_chain': chain,
        'orders': {}}
    for on in order_nos:
        merchant = one(db, 'SELECT merchant FROM sla_cases WHERE case_id=?', (case_id,))['merchant']
        reqs = rows(db, 'SELECT * FROM ingress_requests WHERE merchant=? AND order_no=? ORDER BY at',
                    (merchant, on))
        result['orders'][on] = {
            'requests': reqs,
            'gateway_receipts': rows(db, 'SELECT * FROM gateway_receipts WHERE request_id IN '
                                     '(SELECT request_id FROM ingress_requests WHERE merchant=? AND order_no=?)',
                                     (merchant, on)),
            'cashier': rows(db, 'SELECT * FROM cashier_confirmations WHERE merchant=? AND order_no=?',
                            (merchant, on)),
            'replays': rows(db, 'SELECT * FROM purchase_replays WHERE merchant=? AND order_no=?',
                            (merchant, on)),
            'bank_clearing': rows(db, 'SELECT * FROM bank_clearing WHERE merchant=? AND order_no=?',
                                  (merchant, on)),
            'refunds': rows(db, 'SELECT * FROM refunds WHERE merchant=? AND order_no=?', (merchant, on)),
            'claim_item': one(db, 'SELECT * FROM claim_items WHERE case_id=? AND order_no=?', (case_id, on))}
    return result


def trace_request(db, request_id):
    """Full lifecycle of one customer request and every claim it touched."""
    req = one(db, 'SELECT * FROM ingress_requests WHERE request_id=?', (request_id,))
    if not req:
        return None
    canonical = _canonical(db, request_id)
    # collect the whole chain by walking parent pointers from every node
    chain_ids = [canonical]
    pending = [canonical]
    while pending:
        parent = pending.pop()
        for child in rows(db, 'SELECT request_id FROM ingress_requests WHERE retries_of=?', (parent,)):
            if child['request_id'] not in chain_ids:
                chain_ids.append(child['request_id'])
                pending.append(child['request_id'])
    placeholders = ','.join('?' for _ in chain_ids)
    siblings = rows(db, f'SELECT * FROM ingress_requests WHERE request_id IN ({placeholders}) ORDER BY at',
                    tuple(chain_ids))
    return {
        'request': req, 'canonical': canonical, 'retry_chain': siblings,
        'gateway_receipts': rows(db, f'SELECT * FROM gateway_receipts WHERE request_id IN ({placeholders})',
                                 tuple(chain_ids)),
        'claim_items': rows(db, 'SELECT * FROM claim_items WHERE canonical_request=?', (canonical,)),
        'ledger_entries': rows(db, 'SELECT * FROM ledger_entries WHERE request_id=? ORDER BY at, entry_id',
                               (canonical,))}
