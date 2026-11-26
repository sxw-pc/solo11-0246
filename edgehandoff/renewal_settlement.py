"""Verifiable registrar renewals and auditable multi-party settlement.

This module deliberately separates four facts that the old payment draft
conflated:

* a signed customer mandate for a domain;
* registrar/registry evidence that actually extends the registration;
* the state of a bank payment (authorization, settlement, revocation,
  return, or refund); and
* ledger balances owed to the registrar, agent, customer, or advanced by
  the platform.

A registrar acceptance number is only a pending reference.  A registry
receipt containing the verified effective interval is required before a
``registered`` entitlement is created.  Duplicate submissions may have two
acceptance numbers, but they remain correlated to one renewal purchase and
therefore produce at most one registered renewal.

All money amounts are non-negative integer cents.  The ledger is append-only
and double entry; payment state events preserve the difference between
revoking an authorization and moving money back after settlement.

Upgrade protocol and risk allocation
------------------------------------
1. A signed mandate binds the host, customer, and the agent authorized for
   that order.  A verified local ownership claim is supporting context only.
2. A registrar ``acceptance_no`` is pending evidence.  Only an authentic,
   unique registry receipt carrying the host, registrar order, verified
   effective interval, and a settled payment source creates a
   ``registered`` entitlement.
3. ``plan='guaranteed'`` immediately creates a separate ``promised``
   entitlement and locks platform capital.  The platform therefore bears the
   registrar/registry delivery risk until receipt approval releases the
   deposit.  A broken promise remains immutable and is compensated or
   replaced.
4. ``plan='confirmed_only'`` creates no full-year promise.  Money is settled
   or returned according to the bank state, and any temporary backup entry
   plus migration notice is a platform-borne replacement cost.
5. An authorization revocation only releases a hold.  A bank return and a
   platform refund both reverse settled value, but retain different rail
   events.  Neither operation rewrites the one confirmed registrar fee.
"""

from .store import one, rows, tx

SCHEMA = """
CREATE TABLE IF NOT EXISTS rs_mandates(
    mandate_id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    status TEXT NOT NULL,
    signed_at INTEGER NOT NULL,
    valid_until INTEGER,
    superseded_at INTEGER,
    superseded_by TEXT
);

CREATE TABLE IF NOT EXISTS rs_purchases(
    purchase_id TEXT PRIMARY KEY,
    mandate_id TEXT NOT NULL,
    host TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    plan TEXT NOT NULL CHECK(plan IN ('guaranteed','confirmed_only')),
    requested_from INTEGER NOT NULL,
    requested_until INTEGER NOT NULL,
    term_days INTEGER NOT NULL,
    local_lease_until INTEGER NOT NULL,
    price_cents INTEGER NOT NULL CHECK(price_cents >= 0),
    registrar_fee_cents INTEGER NOT NULL CHECK(registrar_fee_cents >= 0),
    commission_cents INTEGER NOT NULL CHECK(commission_cents >= 0),
    deposit_cents INTEGER NOT NULL DEFAULT 0 CHECK(deposit_cents >= 0),
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rs_submissions(
    submission_id TEXT PRIMARY KEY,
    purchase_id TEXT NOT NULL REFERENCES rs_purchases(purchase_id),
    request_id TEXT,
    registrar_id TEXT NOT NULL,
    registrar_order_id TEXT NOT NULL,
    acceptance_no TEXT NOT NULL,
    submitted_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    disposition TEXT NOT NULL DEFAULT 'primary',
    UNIQUE(registrar_id, acceptance_no)
);

CREATE TABLE IF NOT EXISTS rs_registry_receipts(
    receipt_id TEXT PRIMARY KEY,
    purchase_id TEXT NOT NULL REFERENCES rs_purchases(purchase_id),
    submission_id TEXT NOT NULL,
    registrar_id TEXT NOT NULL,
    registry_id TEXT NOT NULL,
    registry_receipt_no TEXT UNIQUE,
    host TEXT NOT NULL,
    registrar_order_id TEXT NOT NULL,
    not_before INTEGER,
    renew_until INTEGER,
    payment_id TEXT,
    evidence_digest TEXT,
    authentic INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    approved_at INTEGER
);

CREATE TABLE IF NOT EXISTS rs_entitlements(
    entitlement_id TEXT PRIMARY KEY,
    purchase_id TEXT NOT NULL REFERENCES rs_purchases(purchase_id),
    host TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    mandate_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('promised','registered','alternative')),
    status TEXT NOT NULL,
    valid_from INTEGER NOT NULL,
    valid_to INTEGER NOT NULL,
    registrar_id TEXT,
    registrar_order_id TEXT,
    submission_id TEXT,
    registry_receipt_id TEXT,
    payment_id TEXT,
    funding_advance_id TEXT,
    backup_host TEXT,
    source_ref TEXT,
    created_at INTEGER NOT NULL,
    breached_at INTEGER,
    breach_reason TEXT
);

CREATE TABLE IF NOT EXISTS rs_payments(
    payment_id TEXT PRIMARY KEY,
    purchase_id TEXT NOT NULL REFERENCES rs_purchases(purchase_id),
    customer_id TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
    status TEXT NOT NULL,
    authorized_at INTEGER,
    settled_at INTEGER,
    terminal_at INTEGER,
    applied_cents INTEGER NOT NULL DEFAULT 0,
    overpayment_cents INTEGER NOT NULL DEFAULT 0,
    settlement_ref TEXT
);

CREATE TABLE IF NOT EXISTS rs_payment_events(
    event_id TEXT PRIMARY KEY,
    payment_id TEXT NOT NULL REFERENCES rs_payments(payment_id),
    event_type TEXT NOT NULL,
    rail TEXT NOT NULL,
    external_ref TEXT UNIQUE,
    amount_cents INTEGER NOT NULL,
    at INTEGER NOT NULL,
    note TEXT
);

CREATE TABLE IF NOT EXISTS rs_accounts(
    account TEXT PRIMARY KEY,
    root TEXT NOT NULL,
    party_id TEXT,
    normal_side TEXT NOT NULL CHECK(normal_side IN ('debit','credit'))
);

CREATE TABLE IF NOT EXISTS rs_journal(
    entry_id TEXT PRIMARY KEY,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    purchase_id TEXT,
    idempotency_key TEXT UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS rs_ledger(
    line_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id TEXT NOT NULL REFERENCES rs_journal(entry_id),
    at INTEGER NOT NULL,
    account TEXT NOT NULL,
    party_id TEXT,
    debit_cents INTEGER NOT NULL DEFAULT 0 CHECK(debit_cents >= 0),
    credit_cents INTEGER NOT NULL DEFAULT 0 CHECK(credit_cents >= 0),
    purchase_id TEXT,
    ref_type TEXT,
    ref_id TEXT
);

CREATE TABLE IF NOT EXISTS rs_bills(
    bill_id TEXT PRIMARY KEY,
    purchase_id TEXT NOT NULL REFERENCES rs_purchases(purchase_id),
    kind TEXT NOT NULL,
    party_id TEXT NOT NULL,
    account TEXT NOT NULL,
    amount_cents INTEGER NOT NULL CHECK(amount_cents >= 0),
    status TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    settled_at INTEGER,
    external_ref TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS rs_advances(
    advance_id TEXT PRIMARY KEY,
    purchase_id TEXT NOT NULL REFERENCES rs_purchases(purchase_id),
    amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
    purpose TEXT NOT NULL,
    counterparty_id TEXT,
    status TEXT NOT NULL,
    expense_account TEXT,
    created_at INTEGER NOT NULL,
    resolved_at INTEGER,
    note TEXT
);

CREATE TABLE IF NOT EXISTS rs_notices(
    notice_id TEXT PRIMARY KEY,
    purchase_id TEXT NOT NULL REFERENCES rs_purchases(purchase_id),
    kind TEXT NOT NULL,
    old_host TEXT NOT NULL,
    backup_host TEXT,
    agent_id TEXT,
    status TEXT NOT NULL,
    message TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    acknowledged_at INTEGER
);

CREATE TABLE IF NOT EXISTS rs_compensations(
    compensation_id TEXT PRIMARY KEY,
    purchase_id TEXT NOT NULL REFERENCES rs_purchases(purchase_id),
    amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
    form TEXT NOT NULL CHECK(form IN ('cash','credit')),
    status TEXT NOT NULL,
    source TEXT NOT NULL,
    bill_id TEXT NOT NULL,
    awarded_at INTEGER NOT NULL,
    paid_at INTEGER
);

CREATE TABLE IF NOT EXISTS rs_commands(
    request_id TEXT PRIMARY KEY,
    op TEXT NOT NULL,
    input_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rs_ledger_account ON rs_ledger(account);
CREATE INDEX IF NOT EXISTS idx_rs_ledger_purchase ON rs_ledger(purchase_id);
CREATE INDEX IF NOT EXISTS idx_rs_entitlements_purchase ON rs_entitlements(purchase_id);
CREATE INDEX IF NOT EXISTS idx_rs_submissions_purchase ON rs_submissions(purchase_id);
CREATE INDEX IF NOT EXISTS idx_rs_payments_purchase ON rs_payments(purchase_id);
"""

# Normal balance side for account control roots.  Subaccounts may append
# ":party-id"; their side is inherited from the root.
ACCOUNT_SIDES = {
    "platform_available_cash": "debit",
    "guarantee_deposit_locked": "debit",
    "platform_advance_receivable": "debit",
    "customer_receivable": "debit",
    "renewal_revenue": "credit",
    "unearned_revenue": "credit",
    "customer_overpayment": "credit",
    "customer_credit": "credit",
    "registrar_payable": "credit",
    "agent_commission_payable": "credit",
    "alternative_provider_payable": "credit",
    "compensation_payable": "credit",
    "platform_equity": "credit",
    "registrar_cost": "debit",
    "agent_commission_expense": "debit",
    "compensation_expense": "debit",
    "alternative_entry_expense": "debit",
}

STANDARD_ACCOUNTS = {
    "platform_available_cash": ("platform", "debit"),
    "guarantee_deposit_locked": ("platform", "debit"),
    "platform_advance_receivable": ("platform", "debit"),
    "platform_equity": ("platform", "credit"),
    "unearned_revenue": ("platform", "credit"),
    "renewal_revenue": ("platform", "credit"),
    "registrar_cost": ("platform", "debit"),
    "agent_commission_expense": ("platform", "debit"),
    "compensation_expense": ("platform", "debit"),
    "alternative_entry_expense": ("platform", "debit"),
}


def ensure_schema(db):
    """Create renewal-settlement tables in a new or existing store database."""
    db.executescript(SCHEMA)
    for account, (party, side) in STANDARD_ACCOUNTS.items():
        db.execute(
            "INSERT OR IGNORE INTO rs_accounts(account,root,party_id,normal_side) "
            "VALUES(?,?,?,?)",
            (account, account, party, side),
        )


def _root(account):
    return account.split(":", 1)[0]


def _side(account):
    root = _root(account)
    try:
        return ACCOUNT_SIDES[root]
    except KeyError as exc:
        raise ValueError(f"unknown ledger account: {account}") from exc


def _ensure_account(db, account, party_id=None):
    root = _root(account)
    side = ACCOUNT_SIDES[root]
    db.execute(
        "INSERT OR IGNORE INTO rs_accounts(account,root,party_id,normal_side) "
        "VALUES(?,?,?,?)",
        (account, root, party_id, side),
    )


def _post_entry(db, entry_id, at, kind, lines, purchase_id=None, description=None):
    """Post a balanced double-entry journal entry. Caller owns the transaction."""
    if one(db, "SELECT entry_id FROM rs_journal WHERE entry_id=?", (entry_id,)):
        return
    if not lines:
        raise ValueError("journal entry requires lines")

    total_debit = 0
    total_credit = 0
    normalized = []
    for line in lines:
        account = line["account"]
        debit = int(line.get("debit", 0))
        credit = int(line.get("credit", 0))
        if debit < 0 or credit < 0 or (debit and credit) or (not debit and not credit):
            raise ValueError("ledger line must have exactly one positive side")
        _side(account)
        _ensure_account(db, account, line.get("party_id"))
        total_debit += debit
        total_credit += credit
        normalized.append((account, line.get("party_id"), debit, credit,
                           line.get("ref_type"), line.get("ref_id")))

    if total_debit != total_credit or total_debit == 0:
        raise ValueError(f"unbalanced or empty journal entry {entry_id}")

    db.execute(
        "INSERT INTO rs_journal(entry_id,at,kind,purchase_id,idempotency_key,description) "
        "VALUES(?,?,?,?,?,?)",
        (entry_id, at, kind, purchase_id, entry_id, description or kind),
    )
    for account, party_id, debit, credit, ref_type, ref_id in normalized:
        db.execute(
            "INSERT INTO rs_ledger(entry_id,at,account,party_id,debit_cents,"
            "credit_cents,purchase_id,ref_type,ref_id) VALUES(?,?,?,?,?,?,?,?,?)",
            (entry_id, at, account, party_id, debit, credit, purchase_id,
             ref_type, ref_id),
        )


def account_balance(db, account, purchase_id=None):
    """Natural balance: positive for both debit-normal and credit-normal accounts."""
    sql = ("SELECT COALESCE(SUM(debit_cents),0) AS d, "
           "COALESCE(SUM(credit_cents),0) AS c FROM rs_ledger WHERE account=?")
    args = [account]
    if purchase_id is not None:
        sql += " AND purchase_id=?"
        args.append(purchase_id)
    row = db.execute(sql, args).fetchone()
    debit, credit = row[0], row[1]
    raw = int(debit) - int(credit)
    return raw if _side(account) == "debit" else -raw


def balances(db):
    """All known account balances in integer cents."""
    out = {}
    for row in db.execute("SELECT account FROM rs_accounts ORDER BY account"):
        account = row[0] if not isinstance(row, dict) else row["account"]
        out[account] = account_balance(db, account)
    return out


def control_balances(db):
    """Balances summed by control-account root, including party subaccounts."""
    out = {}
    for account, amount in balances(db).items():
        root = _root(account)
        out[root] = out.get(root, 0) + amount
    return out


def summary(db):
    """Convenience cash and obligation totals used by trajectory assertions."""
    controls = control_balances(db)
    payment_row = db.execute(
        "SELECT COALESCE(SUM(CASE WHEN status='settled' THEN amount_cents ELSE 0 END),0) settled, "
        "COALESCE(SUM(CASE WHEN status='authorized' THEN amount_cents ELSE 0 END),0) authorized "
        "FROM rs_payments"
    ).fetchone()
    registered = db.execute(
        "SELECT COUNT(*) FROM rs_entitlements WHERE kind='registered'"
    ).fetchone()[0]
    return {
        "available_cash_cents": controls.get("platform_available_cash", 0),
        "locked_deposit_cents": controls.get("guarantee_deposit_locked", 0),
        "cash_total_cents": (controls.get("platform_available_cash", 0)
                             + controls.get("guarantee_deposit_locked", 0)),
        "platform_advance_outstanding_cents": controls.get("platform_advance_receivable", 0),
        "customer_receivable_cents": controls.get("customer_receivable", 0),
        "customer_overpayment_cents": controls.get("customer_overpayment", 0),
        "customer_credit_cents": controls.get("customer_credit", 0),
        "registrar_payable_cents": controls.get("registrar_payable", 0),
        "agent_commission_payable_cents": controls.get("agent_commission_payable", 0),
        "compensation_payable_cents": controls.get("compensation_payable", 0),
        "renewal_revenue_cents": controls.get("renewal_revenue", 0),
        "registrar_cost_cents": controls.get("registrar_cost", 0),
        "agent_commission_expense_cents": controls.get("agent_commission_expense", 0),
        "compensation_expense_cents": controls.get("compensation_expense", 0),
        "alternative_entry_expense_cents": controls.get("alternative_entry_expense", 0),
        "settled_customer_payments_cents": int(payment_row["settled"]),
        "authorized_hold_cents": int(payment_row["authorized"]),
        "registered_entitlements": int(registered),
    }


def seed_platform_capital(db, amount_cents=50_000, at=0,
                          entry_id="je-opening-platform-capital"):
    """Give the platform enough own cash to post a performance deposit."""
    ensure_schema(db)
    with tx(db):
        if one(db, "SELECT entry_id FROM rs_journal WHERE entry_id=?", (entry_id,)):
            return {"decision": "capital_already_seeded"}
        _post_entry(db, entry_id, at, "opening_capital", [
            {"account": "platform_available_cash", "debit": amount_cents},
            {"account": "platform_equity", "credit": amount_cents},
        ], description="opening platform capital")
        return {"decision": "capital_seeded", "amount_cents": amount_cents}


def sign_mandate(db, mandate_id, host, customer_id, agent_id, signature, at,
                 valid_until=None):
    """Record the customer's signed choice of domain and current agent."""
    ensure_schema(db)
    with tx(db):
        old = one(db, "SELECT * FROM rs_mandates WHERE mandate_id=?", (mandate_id,))
        if old:
            return {"decision": "mandate_exists", "mandate_id": mandate_id}
        if not all([host, customer_id, agent_id, signature]):
            return {"decision": "invalid_mandate"}

        active = one(
            db,
            "SELECT * FROM rs_mandates WHERE host=? AND status='active' ORDER BY signed_at DESC",
            (host,),
        )
        if active and active["customer_id"] != customer_id:
            return {"decision": "domain_customer_conflict"}

        db.execute(
            "INSERT INTO rs_mandates(mandate_id,host,customer_id,agent_id,signature,"
            "status,signed_at,valid_until) VALUES(?,?,?,?,?,'active',?,?)",
            (mandate_id, host, customer_id, agent_id, signature, at, valid_until),
        )
        return {"decision": "mandate_signed", "mandate_id": mandate_id,
                "agent_id": agent_id}


def change_agent(db, host, customer_id, new_agent_id, new_mandate_id, signature, at,
                 valid_until=None):
    """Change only future ordering authority; old purchases keep their agent."""
    ensure_schema(db)
    with tx(db):
        active = one(
            db,
            "SELECT * FROM rs_mandates WHERE host=? AND customer_id=? AND status='active'",
            (host, customer_id),
        )
        if not active:
            return {"decision": "active_mandate_required"}
        if active["agent_id"] == new_agent_id:
            return {"decision": "agent_unchanged", "mandate_id": active["mandate_id"]}
        if one(db, "SELECT mandate_id FROM rs_mandates WHERE mandate_id=?",
               (new_mandate_id,)):
            return {"decision": "mandate_exists"}
        if not signature:
            return {"decision": "customer_signature_required"}

        db.execute(
            "UPDATE rs_mandates SET status='superseded',superseded_at=?,superseded_by=? "
            "WHERE mandate_id=?",
            (at, new_mandate_id, active["mandate_id"]),
        )
        db.execute(
            "INSERT INTO rs_mandates(mandate_id,host,customer_id,agent_id,signature,"
            "status,signed_at,valid_until) VALUES(?,?,?,?,?,'active',?,?)",
            (new_mandate_id, host, customer_id, new_agent_id, signature, at, valid_until),
        )
        return {"decision": "agent_changed", "old_agent_id": active["agent_id"],
                "new_agent_id": new_agent_id, "mandate_id": new_mandate_id}


def reassign_order_agent(db, purchase_id, new_agent_id):
    """Commission attribution on an existing order is immutable."""
    ensure_schema(db)
    with tx(db):
        purchase = one(db, "SELECT agent_id FROM rs_purchases WHERE purchase_id=?",
                       (purchase_id,))
        if not purchase:
            return {"decision": "unknown_purchase"}
        if purchase["agent_id"] == new_agent_id:
            return {"decision": "agent_unchanged", "agent_id": purchase["agent_id"]}
        return {"decision": "agent_reassignment_denied",
                "commission_agent_id": purchase["agent_id"]}


def open_renewal(db, purchase_id, mandate_id, at, *, plan="guaranteed",
                 local_lease_until=365, requested_from=None, term_days=365,
                 requested_until=None, price_cents=10_000,
                 registrar_fee_cents=7_000, commission_cents=1_000,
                 deposit_cents=8_000):
    """Open one renewal intent and issue the customer invoice.

    Multiple registrar submissions are children of this one purchase.  This
    is the correlation that prevents duplicate acceptance numbers from
    becoming multiple renewal years.
    """
    ensure_schema(db)
    with tx(db):
        if one(db, "SELECT * FROM rs_purchases WHERE purchase_id=?", (purchase_id,)):
            return {"decision": "purchase_exists", "purchase_id": purchase_id}
        mandate = one(db, "SELECT * FROM rs_mandates WHERE mandate_id=?", (mandate_id,))
        if not mandate or mandate["status"] != "active":
            return {"decision": "active_mandate_required"}
        if plan not in ("guaranteed", "confirmed_only"):
            return {"decision": "invalid_plan"}
        if term_days <= 0 or local_lease_until < 0:
            return {"decision": "invalid_interval"}
        if min(price_cents, registrar_fee_cents, commission_cents, deposit_cents) < 0:
            return {"decision": "invalid_amount"}

        requested_from = local_lease_until if requested_from is None else requested_from
        requested_until = (requested_from + term_days if requested_until is None
                           else requested_until)
        if requested_until <= requested_from:
            return {"decision": "invalid_interval"}

        db.execute(
            "INSERT INTO rs_purchases(purchase_id,mandate_id,host,customer_id,agent_id,"
            "plan,requested_from,requested_until,term_days,local_lease_until,"
            "price_cents,registrar_fee_cents,commission_cents,deposit_cents,status,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'opened', ?, ?)",
            (purchase_id, mandate_id, mandate["host"], mandate["customer_id"],
             mandate["agent_id"], plan, requested_from, requested_until, term_days,
             local_lease_until, price_cents, registrar_fee_cents, commission_cents,
             deposit_cents, at, at),
        )

        invoice_id = f"bill-customer-{purchase_id}"
        ar = f"customer_receivable:{mandate['customer_id']}"
        db.execute(
            "INSERT INTO rs_bills(bill_id,purchase_id,kind,party_id,account,"
            "amount_cents,status,issued_at,description) VALUES(?,?,?,?,?,?, 'issued', ?,?)",
            (invoice_id, purchase_id, "customer_invoice", mandate["customer_id"], ar,
             price_cents, at, "signed renewal invoice"),
        )
        _post_entry(db, f"je-invoice-{purchase_id}", at, "customer_invoice", [
            {"account": ar, "debit": price_cents, "party_id": mandate["customer_id"]},
            {"account": "unearned_revenue", "credit": price_cents},
        ], purchase_id=purchase_id, description="issue customer renewal invoice")

        return {"decision": "renewal_opened", "purchase_id": purchase_id,
                "invoice_id": invoice_id, "agent_id": mandate["agent_id"]}


def authorize_payment(db, payment_id, purchase_id, amount_cents, at, *,
                      source_ref="bank-card", auth_ref=None):
    """Record a revocable authorization hold. No settled cash movement occurs."""
    ensure_schema(db)
    with tx(db):
        old = one(db, "SELECT * FROM rs_payments WHERE payment_id=?", (payment_id,))
        if old:
            if old["purchase_id"] == purchase_id and old["amount_cents"] == amount_cents:
                return {"decision": "authorization_recorded", "payment_id": payment_id,
                        "status": old["status"]}
            return {"decision": "payment_conflict"}
        purchase = one(db, "SELECT * FROM rs_purchases WHERE purchase_id=?",
                       (purchase_id,))
        if not purchase or amount_cents <= 0:
            return {"decision": "invalid_payment"}

        auth_ref = auth_ref or f"auth-{payment_id}"
        db.execute(
            "INSERT INTO rs_payments(payment_id,purchase_id,customer_id,source_ref,"
            "amount_cents,status,authorized_at) VALUES(?,?,?,?,?, 'authorized', ?)",
            (payment_id, purchase_id, purchase["customer_id"], source_ref,
             amount_cents, at),
        )
        db.execute(
            "INSERT INTO rs_payment_events(event_id,payment_id,event_type,rail,"
            "external_ref,amount_cents,at,note) VALUES(?,?, 'authorization','bank',?,?,?,?)",
            (f"evt-{payment_id}-authorization", payment_id, auth_ref, amount_cents, at,
             "revocable authorization hold"),
        )
        return {"decision": "authorized", "payment_id": payment_id,
                "hold_cents": amount_cents}


def settle_payment(db, payment_id, at, settlement_ref, *, event_id=None):
    """Convert an authorization to settled/cleared funds."""
    ensure_schema(db)
    with tx(db):
        payment = one(db, "SELECT * FROM rs_payments WHERE payment_id=?", (payment_id,))
        if not payment:
            return {"decision": "unknown_payment"}
        if payment["status"] == "settled":
            return {"decision": "already_settled", "payment_id": payment_id}
        if payment["status"] != "authorized":
            return {"decision": "payment_not_settleable", "status": payment["status"]}

        purchase_id = payment["purchase_id"]
        customer = payment["customer_id"]
        amount = payment["amount_cents"]
        ar = f"customer_receivable:{customer}"
        outstanding = max(0, account_balance(db, ar, purchase_id=purchase_id))
        applied = min(amount, outstanding)
        overpayment = amount - applied
        over_account = f"customer_overpayment:{customer}"

        lines = [{"account": "platform_available_cash", "debit": amount}]
        if applied:
            lines.append({"account": ar, "credit": applied, "party_id": customer})
        if overpayment:
            lines.append({"account": over_account, "credit": overpayment,
                          "party_id": customer})

        event_id = event_id or f"evt-{payment_id}-settlement"
        _post_entry(db, event_id, at, "payment_settlement", lines,
                    purchase_id=purchase_id, description=settlement_ref)
        db.execute(
            "UPDATE rs_payments SET status='settled',settled_at=?,applied_cents=?,"
            "overpayment_cents=?,settlement_ref=? WHERE payment_id=?",
            (at, applied, overpayment, settlement_ref, payment_id),
        )
        db.execute(
            "INSERT INTO rs_payment_events(event_id,payment_id,event_type,rail,"
            "external_ref,amount_cents,at,note) VALUES(?,?,'settlement','bank',?,?,?,?)",
            (event_id, payment_id, settlement_ref, amount, at, "funds cleared"),
        )
        if applied:
            receivable_after = account_balance(db, ar, purchase_id=purchase_id)
            invoice_status = "paid" if receivable_after == 0 else "partially_paid"
            db.execute(
                "UPDATE rs_bills SET status=?,settled_at=? "
                "WHERE bill_id=? AND kind='customer_invoice' AND status<>'cancelled'",
                (invoice_status, at if invoice_status == "paid" else None,
                 f"bill-customer-{purchase_id}"),
            )
        return {"decision": "settled", "payment_id": payment_id,
                "applied_cents": applied, "overpayment_cents": overpayment}


def revoke_authorization(db, payment_id, at, revocation_ref, *, event_id=None):
    """Void/release a pre-authorization. This is not a refund: no cash settled."""
    ensure_schema(db)
    with tx(db):
        payment = one(db, "SELECT * FROM rs_payments WHERE payment_id=?", (payment_id,))
        if not payment:
            return {"decision": "unknown_payment"}
        if payment["status"] == "authorization_revoked":
            return {"decision": "authorization_revoked", "refund_posted": False}
        if payment["status"] != "authorized":
            return {"decision": "authorization_not_revocable",
                    "status": payment["status"]}

        event_id = event_id or f"evt-{payment_id}-revocation"
        db.execute(
            "UPDATE rs_payments SET status='authorization_revoked',terminal_at=? "
            "WHERE payment_id=?",
            (at, payment_id),
        )
        db.execute(
            "INSERT INTO rs_payment_events(event_id,payment_id,event_type,rail,"
            "external_ref,amount_cents,at,note) "
            "VALUES(?,?,'authorization_revocation','bank',?,?,?,?)",
            (event_id, payment_id, revocation_ref, payment["amount_cents"], at,
             "hold released; no settled funds returned"),
        )
        return {"decision": "authorization_revoked", "refund_posted": False}


def _reverse_settlement(db, payment, event_id, at, external_ref, event_type, rail, note):
    purchase_id = payment["purchase_id"]
    customer = payment["customer_id"]
    amount = payment["amount_cents"]
    lines = [{"account": "platform_available_cash", "credit": amount}]
    if payment["overpayment_cents"]:
        lines.append({
            "account": f"customer_overpayment:{customer}",
            "debit": payment["overpayment_cents"],
            "party_id": customer,
        })
    if payment["applied_cents"]:
        lines.append({
            "account": f"customer_receivable:{customer}",
            "debit": payment["applied_cents"],
            "party_id": customer,
        })

    _post_entry(db, event_id, at, f"payment_{event_type}", lines,
                purchase_id=purchase_id, description=external_ref)
    new_status = "returned" if event_type == "return" else "refunded"
    db.execute(
        "UPDATE rs_payments SET status=?,terminal_at=? WHERE payment_id=?",
        (new_status, at, payment["payment_id"]),
    )
    db.execute(
        "INSERT INTO rs_payment_events(event_id,payment_id,event_type,rail,"
        "external_ref,amount_cents,at,note) VALUES(?,?,?,?,?,?,?,?)",
        (event_id, payment["payment_id"], event_type, rail, external_ref, amount, at, note),
    )
    if payment["applied_cents"]:
        ar = f"customer_receivable:{customer}"
        receivable_after = account_balance(db, ar, purchase_id=purchase_id)
        invoice_status = "issued" if receivable_after > 0 else "paid"
        db.execute(
            "UPDATE rs_bills SET status=?,settled_at=NULL "
            "WHERE bill_id=? AND kind='customer_invoice' AND status<>'cancelled'",
            (invoice_status, f"bill-customer-{purchase_id}"),
        )
    return {"decision": new_status, "payment_id": payment["payment_id"],
            "refund_posted": event_type == "refund",
            "bank_return": event_type == "return"}


def refund_payment(db, refund_id, payment_id, at, refund_ref):
    """Move settled money back on an actual platform-initiated refund."""
    ensure_schema(db)
    with tx(db):
        payment = one(db, "SELECT * FROM rs_payments WHERE payment_id=?", (payment_id,))
        if not payment:
            return {"decision": "unknown_payment"}
        if payment["status"] == "refunded":
            return {"decision": "already_refunded", "refund_posted": True}
        if payment["status"] != "settled":
            return {"decision": "refund_not_available", "status": payment["status"]}
        return _reverse_settlement(
            db, payment, refund_id, at, refund_ref, "refund", "platform",
            "actual refund of settled funds")


def return_payment(db, return_id, payment_id, at, bank_return_ref):
    """Record a bank return/chargeback of an already settled payment."""
    ensure_schema(db)
    with tx(db):
        payment = one(db, "SELECT * FROM rs_payments WHERE payment_id=?", (payment_id,))
        if not payment:
            return {"decision": "unknown_payment"}
        if payment["status"] == "returned":
            return {"decision": "already_returned"}
        if payment["status"] != "settled":
            return {"decision": "return_not_available", "status": payment["status"]}
        return _reverse_settlement(
            db, payment, return_id, at, bank_return_ref, "return", "bank",
            "bank returned or reversed settled funds")


def cancel_customer_invoice(db, purchase_id, at, reason="renewal_not_delivered"):
    """Cancel an invoice after its settled payment has been reversed.

    A refund deliberately re-opens customer receivable so the payment rail is
    auditable.  This separate event clears that receivable against the
    previously recognized unearned revenue and cancels the invoice.
    """
    ensure_schema(db)
    with tx(db):
        purchase = one(db, "SELECT * FROM rs_purchases WHERE purchase_id=?",
                       (purchase_id,))
        if not purchase:
            return {"decision": "unknown_purchase"}
        bill_id = f"bill-customer-{purchase_id}"
        bill = one(db, "SELECT * FROM rs_bills WHERE bill_id=?", (bill_id,))
        if not bill:
            return {"decision": "invoice_not_found"}
        if bill["status"] == "cancelled":
            return {"decision": "invoice_already_cancelled"}

        ar = f"customer_receivable:{purchase['customer_id']}"
        outstanding = account_balance(db, ar, purchase_id=purchase_id)
        if outstanding != bill["amount_cents"]:
            return {"decision": "invoice_cancellation_requires_payment_reversal",
                    "receivable_cents": outstanding,
                    "invoice_cents": bill["amount_cents"]}

        _post_entry(db, f"je-invoice-cancel-{purchase_id}", at,
                    "cancel_customer_invoice", [
            {"account": "unearned_revenue", "debit": bill["amount_cents"]},
            {"account": ar, "credit": bill["amount_cents"],
             "party_id": purchase["customer_id"]},
        ], purchase_id=purchase_id, description=reason)
        db.execute("UPDATE rs_bills SET status='cancelled' WHERE bill_id=?", (bill_id,))
        db.execute("UPDATE rs_purchases SET status='cancelled',updated_at=? WHERE purchase_id=?",
                   (at, purchase_id))
        return {"decision": "invoice_cancelled", "bill_id": bill_id}


def submit_to_registrar(db, submission_id, purchase_id, acceptance_no, at, *,
                        request_id=None, registrar_id="registrar-b",
                        registrar_order_id=None):
    """Record one submission and the registrar's acceptance number.

    An acceptance number means 'request accepted for processing', not that
    the registry extended the domain.
    """
    ensure_schema(db)
    with tx(db):
        old = one(db, "SELECT * FROM rs_submissions WHERE submission_id=?",
                  (submission_id,))
        if old:
            return {"decision": "acceptance_recorded", "submission_id": submission_id,
                    "status": old["status"]}
        purchase = one(db, "SELECT * FROM rs_purchases WHERE purchase_id=?",
                       (purchase_id,))
        if not purchase:
            return {"decision": "unknown_purchase"}
        duplicate_acceptance = one(
            db,
            "SELECT * FROM rs_submissions WHERE registrar_id=? AND acceptance_no=?",
            (registrar_id, acceptance_no),
        )
        if duplicate_acceptance:
            return {"decision": "acceptance_conflict"}

        registrar_order_id = registrar_order_id or f"bord-{purchase_id}"
        db.execute(
            "INSERT INTO rs_submissions(submission_id,purchase_id,request_id,"
            "registrar_id,registrar_order_id,acceptance_no,submitted_at,status,"
            "disposition) VALUES(?,?,?,?,?,?,?, 'accepted_pending','primary')",
            (submission_id, purchase_id, request_id, registrar_id,
             registrar_order_id, acceptance_no, at),
        )
        return {"decision": "accepted_pending", "submission_id": submission_id,
                "acceptance_no": acceptance_no,
                "registrar_order_id": registrar_order_id}


def _eligible_settled_payment(db, purchase_id, payment_id=None):
    if payment_id:
        payment = one(db, "SELECT * FROM rs_payments WHERE payment_id=? AND purchase_id=?",
                      (payment_id, purchase_id))
        if payment and payment["status"] == "settled":
            return payment
        return None
    return one(
        db,
        "SELECT * FROM rs_payments WHERE purchase_id=? AND status='settled' "
        "ORDER BY settled_at,payment_id LIMIT 1",
        (purchase_id,),
    )


def confirm_registry_receipt(db, receipt_id, purchase_id, submission_id,
                             registry_receipt_no, not_before, renew_until, at, *,
                             host=None, authentic=True, evidence_digest=None,
                             registry_id="registry-main", payment_id=None,
                             entitlement_id=None):
    """Upgrade one purchase to a registered entitlement from registry evidence.

    Required evidence is an authentic, unique registry receipt bound to the
    signed host, registrar submission/order, and a settled payment source.
    A second acceptance number can never supply this evidence by itself.
    """
    ensure_schema(db)
    with tx(db):
        purchase = one(db, "SELECT * FROM rs_purchases WHERE purchase_id=?",
                       (purchase_id,))
        if not purchase:
            return {"decision": "unknown_purchase"}

        existing_receipt = one(db, "SELECT * FROM rs_registry_receipts WHERE receipt_id=?",
                               (receipt_id,))
        if existing_receipt and existing_receipt["status"] == "approved":
            return {"decision": "renewal_confirmed",
                    "entitlement_id": f"ent-reg-{purchase_id}", "idempotent": True}

        submission = one(db, "SELECT * FROM rs_submissions WHERE submission_id=?",
                         (submission_id,))
        if not submission or submission["purchase_id"] != purchase_id:
            return {"decision": "submission_mismatch"}
        if host is not None and host != purchase["host"]:
            return {"decision": "host_mismatch"}
        if renew_until <= not_before:
            return {"decision": "invalid_registry_interval"}

        # Untrusted or incomplete external evidence is retained as rejected
        # evidence but cannot create an entitlement.  It must never replace
        # an already trusted receipt carrying the same registry number.
        receipt_conflict = one(
            db,
            "SELECT receipt_id FROM rs_registry_receipts "
            "WHERE registry_receipt_no=? AND receipt_id<>?",
            (registry_receipt_no, receipt_id),
        ) if registry_receipt_no else None
        if receipt_conflict:
            return {"decision": "registry_receipt_conflict"}

        if not authentic or not registry_receipt_no or not evidence_digest:
            db.execute(
                "INSERT INTO rs_registry_receipts(receipt_id,purchase_id,"
                "submission_id,registrar_id,registry_id,registry_receipt_no,host,"
                "registrar_order_id,not_before,renew_until,evidence_digest,authentic,"
                "status,received_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'unverified',?) "
                "ON CONFLICT(receipt_id) DO UPDATE SET status='unverified',"
                "authentic=excluded.authentic,evidence_digest=excluded.evidence_digest",
                (receipt_id, purchase_id, submission_id, submission["registrar_id"],
                 registry_id, registry_receipt_no, purchase["host"],
                 submission["registrar_order_id"], not_before, renew_until,
                 evidence_digest, 1 if authentic else 0, at),
            )
            return {"decision": "evidence_unverified"}

        prior = one(
            db,
            "SELECT * FROM rs_registry_receipts WHERE purchase_id=? AND status='approved' "
            "ORDER BY approved_at LIMIT 1",
            (purchase_id,),
        )
        if prior:
            db.execute(
                "INSERT OR REPLACE INTO rs_registry_receipts(receipt_id,purchase_id,"
                "submission_id,registrar_id,registry_id,registry_receipt_no,host,"
                "registrar_order_id,not_before,renew_until,payment_id,evidence_digest,"
                "authentic,status,received_at,approved_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'duplicate_ignored', ?,?)",
                (receipt_id, purchase_id, submission_id, submission["registrar_id"],
                 registry_id, registry_receipt_no, purchase["host"],
                 submission["registrar_order_id"], not_before, renew_until, payment_id,
                 evidence_digest, 1, at, at),
            )
            return {"decision": "renewal_already_confirmed",
                    "entitlement_id": f"ent-reg-{purchase_id}"}

        payment = _eligible_settled_payment(db, purchase_id, payment_id)
        if not payment:
            return {"decision": "settled_payment_source_required"}

        entitlement_id = entitlement_id or f"ent-reg-{purchase_id}"
        db.execute(
            "INSERT INTO rs_registry_receipts(receipt_id,purchase_id,submission_id,"
            "registrar_id,registry_id,registry_receipt_no,host,registrar_order_id,"
            "not_before,renew_until,payment_id,evidence_digest,authentic,status,"
            "received_at,approved_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'approved', ?,?) "
            "ON CONFLICT(receipt_id) DO UPDATE SET submission_id=excluded.submission_id,"
            "not_before=excluded.not_before,renew_until=excluded.renew_until,"
            "payment_id=excluded.payment_id,evidence_digest=excluded.evidence_digest,"
            "authentic=1,status='approved',approved_at=excluded.approved_at",
            (receipt_id, purchase_id, submission_id, submission["registrar_id"],
             registry_id, registry_receipt_no, purchase["host"],
             submission["registrar_order_id"], not_before, renew_until,
             payment["payment_id"], evidence_digest, 1, at, at),
        )
        db.execute(
            "INSERT INTO rs_entitlements(entitlement_id,purchase_id,host,customer_id,"
            "mandate_id,kind,status,valid_from,valid_to,registrar_id,"
            "registrar_order_id,submission_id,registry_receipt_id,payment_id,"
            "source_ref,created_at) VALUES(?,?,?,?,?,?,'active',?,?,?,?,?,?,?,?,?)",
            (entitlement_id, purchase_id, purchase["host"], purchase["customer_id"],
             purchase["mandate_id"], "registered", not_before, renew_until,
             submission["registrar_id"], submission["registrar_order_id"],
             submission_id, receipt_id, payment["payment_id"],
             f"registry:{registry_receipt_no}", at),
        )
        db.execute(
            "UPDATE rs_submissions SET status='confirmed' WHERE submission_id=?",
            (submission_id,),
        )
        db.execute(
            "UPDATE rs_submissions SET status='duplicate_acceptance',"
            "disposition='duplicate' WHERE purchase_id=? AND submission_id<>? "
            "AND status='accepted_pending'",
            (purchase_id, submission_id),
        )

        # Earn customer revenue now that the registry interval is proven.
        _post_entry(db, f"je-revenue-{purchase_id}", at, "recognize_revenue", [
            {"account": "unearned_revenue", "debit": purchase["price_cents"]},
            {"account": "renewal_revenue", "credit": purchase["price_cents"]},
        ], purchase_id=purchase_id)

        registrar_account = (f"registrar_payable:{submission['registrar_id']}")
        registrar_bill = f"bill-registrar-{purchase_id}"
        db.execute(
            "INSERT INTO rs_bills(bill_id,purchase_id,kind,party_id,account,"
            "amount_cents,status,issued_at,description) "
            "VALUES(?,?, 'registrar_fee',?,?,?, 'open', ?,?)",
            (registrar_bill, purchase_id, submission["registrar_id"],
             registrar_account, purchase["registrar_fee_cents"], at,
             "one registry-confirmed renewal"),
        )
        _post_entry(db, f"je-regcost-{purchase_id}", at, "registrar_cost", [
            {"account": "registrar_cost", "debit": purchase["registrar_fee_cents"]},
            {"account": registrar_account, "credit": purchase["registrar_fee_cents"],
             "party_id": submission["registrar_id"]},
        ], purchase_id=purchase_id)

        # Attribution is copied from the immutable purchase row, not the
        # customer's current agent mandate.
        agent_account = f"agent_commission_payable:{purchase['agent_id']}"
        commission_bill = f"bill-commission-{purchase_id}"
        db.execute(
            "INSERT INTO rs_bills(bill_id,purchase_id,kind,party_id,account,"
            "amount_cents,status,issued_at,description) "
            "VALUES(?,?, 'agent_commission',?,?,?, 'open', ?,?)",
            (commission_bill, purchase_id, purchase["agent_id"], agent_account,
             purchase["commission_cents"], at, "original order commission"),
        )
        _post_entry(db, f"je-commcost-{purchase_id}", at, "agent_commission", [
            {"account": "agent_commission_expense",
             "debit": purchase["commission_cents"]},
            {"account": agent_account, "credit": purchase["commission_cents"],
             "party_id": purchase["agent_id"]},
        ], purchase_id=purchase_id)

        released_deposit = account_balance(
            db, "guarantee_deposit_locked", purchase_id=purchase_id)
        if released_deposit > 0:
            _post_entry(db, f"je-deposit-release-{purchase_id}", at,
                        "release_guarantee_deposit", [
                {"account": "platform_available_cash", "debit": released_deposit},
                {"account": "guarantee_deposit_locked", "credit": released_deposit},
            ], purchase_id=purchase_id)

        new_status = ("registry_confirmed_after_breach"
                      if purchase["status"] == "promise_breached"
                      else "registry_confirmed")
        db.execute("UPDATE rs_purchases SET status=?,updated_at=? WHERE purchase_id=?",
                   (new_status, at, purchase_id))
        return {"decision": "renewal_confirmed", "entitlement_id": entitlement_id,
                "registry_receipt_no": registry_receipt_no,
                "valid_from": not_before, "valid_to": renew_until,
                "payment_id": payment["payment_id"],
                "released_deposit_cents": released_deposit}


def issue_guaranteed_promise(db, purchase_id, at, *, entitlement_id=None,
                             deposit_cents=None):
    """Issue an immediate platform-backed full-year promise.

    The resulting entitlement is explicitly ``promised`` rather than
    ``registered``.  The platform locks its own deposit and therefore bears
    registrar/registry delivery risk until an approved receipt arrives.
    """
    ensure_schema(db)
    with tx(db):
        purchase = one(db, "SELECT * FROM rs_purchases WHERE purchase_id=?",
                       (purchase_id,))
        if not purchase:
            return {"decision": "unknown_purchase"}
        existing = one(
            db,
            "SELECT * FROM rs_entitlements WHERE purchase_id=? AND kind='promised'",
            (purchase_id,),
        )
        if existing:
            return {"decision": "promise_already_issued",
                    "entitlement_id": existing["entitlement_id"],
                    "status": existing["status"]}
        if purchase["plan"] != "guaranteed":
            return {"decision": "guarantee_plan_required"}

        payment = _eligible_settled_payment(db, purchase_id)
        if not payment:
            return {"decision": "settled_payment_source_required"}

        deposit = purchase["deposit_cents"] if deposit_cents is None else deposit_cents
        available = account_balance(db, "platform_available_cash")
        if available < deposit:
            return {"decision": "insufficient_platform_deposit",
                    "available_cents": available, "required_cents": deposit}

        entitlement_id = entitlement_id or f"ent-promise-{purchase_id}"
        if deposit:
            _post_entry(db, f"je-deposit-lock-{purchase_id}", at,
                        "lock_guarantee_deposit", [
                {"account": "guarantee_deposit_locked", "debit": deposit},
                {"account": "platform_available_cash", "credit": deposit},
            ], purchase_id=purchase_id)

        db.execute(
            "INSERT INTO rs_entitlements(entitlement_id,purchase_id,host,customer_id,"
            "mandate_id,kind,status,valid_from,valid_to,payment_id,source_ref,"
            "created_at) VALUES(?,?,?,?,?, 'promised','active',?,?,?,?,?)",
            (entitlement_id, purchase_id, purchase["host"], purchase["customer_id"],
             purchase["mandate_id"], purchase["requested_from"],
             purchase["requested_until"], payment["payment_id"],
             f"platform_deposit:{deposit}", at),
        )
        db.execute("UPDATE rs_purchases SET status='promised',updated_at=? WHERE purchase_id=?",
                   (at, purchase_id))
        return {"decision": "guaranteed_promised", "entitlement_id": entitlement_id,
                "valid_from": purchase["requested_from"],
                "valid_to": purchase["requested_until"],
                "deposit_locked_cents": deposit}


def record_promise_breach(db, purchase_id, at, reason):
    """Mark the signed-out promise wrong without deleting or rewriting it."""
    ensure_schema(db)
    with tx(db):
        promise = one(
            db,
            "SELECT * FROM rs_entitlements WHERE purchase_id=? AND kind='promised' "
            "ORDER BY created_at LIMIT 1",
            (purchase_id,),
        )
        if not promise:
            return {"decision": "promise_not_found"}
        if promise["status"] == "breached":
            return {"decision": "promise_already_breached",
                    "entitlement_id": promise["entitlement_id"]}

        db.execute(
            "UPDATE rs_entitlements SET status='breached',breached_at=?,"
            "breach_reason=? WHERE entitlement_id=?",
            (at, reason, promise["entitlement_id"]),
        )
        db.execute("UPDATE rs_purchases SET status='promise_breached',updated_at=? "
                   "WHERE purchase_id=?", (at, purchase_id))
        return {"decision": "promise_breached",
                "entitlement_id": promise["entitlement_id"],
                "valid_from": promise["valid_from"], "valid_to": promise["valid_to"]}


def award_compensation(db, compensation_id, purchase_id, amount_cents, at, *,
                       form="cash", pay_now=True, from_deposit=True):
    """Award and optionally pay compensation for a broken renewal promise."""
    ensure_schema(db)
    with tx(db):
        purchase = one(db, "SELECT * FROM rs_purchases WHERE purchase_id=?",
                       (purchase_id,))
        if not purchase:
            return {"decision": "unknown_purchase"}
        promise = one(
            db,
            "SELECT status FROM rs_entitlements WHERE purchase_id=? AND kind='promised'",
            (purchase_id,),
        )
        if not promise or promise["status"] != "breached":
            return {"decision": "breach_required"}
        if amount_cents <= 0 or form not in ("cash", "credit"):
            return {"decision": "invalid_compensation"}
        if one(db, "SELECT compensation_id FROM rs_compensations WHERE compensation_id=?",
               (compensation_id,)):
            return {"decision": "compensation_exists"}

        # Check availability before writing any leg of the compensation event.
        pay_from_deposit = form == "cash" and pay_now and from_deposit
        pay_from_cash = form == "cash" and pay_now and not from_deposit
        if pay_from_deposit:
            locked = account_balance(
                db, "guarantee_deposit_locked", purchase_id=purchase_id)
            if locked < amount_cents:
                return {"decision": "insufficient_deposit",
                        "locked_cents": locked, "required_cents": amount_cents}
        if pay_from_cash:
            available = account_balance(db, "platform_available_cash")
            if available < amount_cents:
                return {"decision": "insufficient_platform_cash",
                        "available_cents": available, "required_cents": amount_cents}

        customer = purchase["customer_id"]
        payable_account = f"compensation_payable:{customer}"
        bill_id = f"bill-compensation-{compensation_id}"
        db.execute(
            "INSERT INTO rs_bills(bill_id,purchase_id,kind,party_id,account,"
            "amount_cents,status,issued_at,description) "
            "VALUES(?,?, 'compensation',?,?,?, 'approved', ?,?)",
            (bill_id, purchase_id, customer, payable_account, amount_cents, at,
             "wrong renewal promise compensation"),
        )
        _post_entry(db, f"je-comp-award-{compensation_id}", at,
                    "compensation_awarded", [
            {"account": "compensation_expense", "debit": amount_cents},
            {"account": payable_account, "credit": amount_cents, "party_id": customer},
        ], purchase_id=purchase_id)

        source = "deposit" if from_deposit and pay_now else "operating_cash"
        status = "approved"
        paid_at = None

        if form == "credit":
            credit_account = f"customer_credit:{customer}"
            _post_entry(db, f"je-comp-credit-{compensation_id}", at,
                        "compensation_credit", [
                {"account": payable_account, "debit": amount_cents, "party_id": customer},
                {"account": credit_account, "credit": amount_cents, "party_id": customer},
            ], purchase_id=purchase_id)
            status = "credit_issued"
            source = "customer_credit"
        elif pay_now:
            if from_deposit:
                credit_account = "guarantee_deposit_locked"
            else:
                credit_account = "platform_available_cash"
            _post_entry(db, f"je-comp-pay-{compensation_id}", at,
                        "compensation_paid", [
                {"account": payable_account, "debit": amount_cents, "party_id": customer},
                {"account": credit_account, "credit": amount_cents},
            ], purchase_id=purchase_id)
            status = "paid"
            paid_at = at

        db.execute(
            "INSERT INTO rs_compensations(compensation_id,purchase_id,amount_cents,"
            "form,status,source,bill_id,awarded_at,paid_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (compensation_id, purchase_id, amount_cents, form, status, source,
             bill_id, at, paid_at),
        )
        return {"decision": "compensation_" + ("paid" if status == "paid" else status),
                "compensation_id": compensation_id, "status": status}


def release_guarantee_deposit(db, purchase_id, at):
    """Release any remaining purchase-specific locked platform deposit."""
    ensure_schema(db)
    with tx(db):
        purchase = one(db, "SELECT purchase_id FROM rs_purchases WHERE purchase_id=?",
                       (purchase_id,))
        if not purchase:
            return {"decision": "unknown_purchase"}
        amount = account_balance(db, "guarantee_deposit_locked",
                                 purchase_id=purchase_id)
        if amount <= 0:
            return {"decision": "deposit_already_released", "released_cents": 0}
        _post_entry(db, f"je-deposit-release-manual-{purchase_id}-{at}", at,
                    "release_guarantee_deposit", [
            {"account": "platform_available_cash", "debit": amount},
            {"account": "guarantee_deposit_locked", "credit": amount},
        ], purchase_id=purchase_id)
        return {"decision": "deposit_released", "released_cents": amount}


def advance_platform_funds(db, advance_id, purchase_id, amount_cents, at, *,
                           purpose="registrar_fee", counterparty_id=None, note=None):
    """Record platform money advanced on a purchase and its追索 balance."""
    ensure_schema(db)
    with tx(db):
        if one(db, "SELECT advance_id FROM rs_advances WHERE advance_id=?",
               (advance_id,)):
            return {"decision": "advance_exists"}
        purchase = one(db, "SELECT purchase_id FROM rs_purchases WHERE purchase_id=?",
                       (purchase_id,))
        if not purchase or amount_cents <= 0:
            return {"decision": "invalid_advance"}
        _post_entry(db, f"je-advance-{advance_id}", at, "platform_advance", [
            {"account": "platform_advance_receivable", "debit": amount_cents},
            {"account": "platform_available_cash", "credit": amount_cents},
        ], purchase_id=purchase_id)
        db.execute(
            "INSERT INTO rs_advances(advance_id,purchase_id,amount_cents,purpose,"
            "counterparty_id,status,created_at,note) VALUES(?,?,?,?,?, 'outstanding', ?,?)",
            (advance_id, purchase_id, amount_cents, purpose, counterparty_id, at, note),
        )
        return {"decision": "advanced", "advance_id": advance_id,
                "outstanding_cents": amount_cents}


def recover_platform_advance(db, advance_id, at, *, recovery_ref=None):
    """Cash recovery of a previously outstanding platform advance."""
    ensure_schema(db)
    with tx(db):
        advance = one(db, "SELECT * FROM rs_advances WHERE advance_id=?", (advance_id,))
        if not advance:
            return {"decision": "unknown_advance"}
        if advance["status"] == "recovered":
            return {"decision": "advance_already_recovered"}
        if advance["status"] != "outstanding":
            return {"decision": "advance_not_recoverable", "status": advance["status"]}

        _post_entry(db, f"je-advance-recover-{advance_id}", at,
                    "platform_advance_recovery", [
            {"account": "platform_available_cash", "debit": advance["amount_cents"]},
            {"account": "platform_advance_receivable",
             "credit": advance["amount_cents"]},
        ], purchase_id=advance["purchase_id"], description=recovery_ref)
        db.execute("UPDATE rs_advances SET status='recovered',resolved_at=? WHERE advance_id=?",
                   (at, advance_id))
        return {"decision": "advance_recovered", "advance_id": advance_id}


def bear_platform_advance(db, advance_id, at, *, expense_account=None):
    """Convert an advance to a platform-borne cost (for example backup entry)."""
    ensure_schema(db)
    with tx(db):
        advance = one(db, "SELECT * FROM rs_advances WHERE advance_id=?", (advance_id,))
        if not advance:
            return {"decision": "unknown_advance"}
        if advance["status"] == "borne_by_platform":
            return {"decision": "advance_already_borne"}
        if advance["status"] != "outstanding":
            return {"decision": "advance_not_bearable", "status": advance["status"]}

        if expense_account is None:
            expense_account = {
                "backup_entry": "alternative_entry_expense",
                "compensation": "compensation_expense",
            }.get(advance["purpose"], "alternative_entry_expense")
        _post_entry(db, f"je-advance-bear-{advance_id}", at,
                    "platform_bears_advance", [
            {"account": expense_account, "debit": advance["amount_cents"]},
            {"account": "platform_advance_receivable",
             "credit": advance["amount_cents"]},
        ], purchase_id=advance["purchase_id"])
        db.execute(
            "UPDATE rs_advances SET status='borne_by_platform',resolved_at=?,"
            "expense_account=? WHERE advance_id=?",
            (at, expense_account, advance_id),
        )
        return {"decision": "advance_borne_by_platform", "advance_id": advance_id,
                "expense_account": expense_account}


def secure_backup_entry(db, backup_id, purchase_id, backup_host, at, *,
                        valid_from=None, valid_days=30, cost_cents=1_500,
                        provider_id="backup-registry", notice_id=None,
                        advance_id=None, bear_now=True):
    """Buy a short-term alternative entry and issue the migration notice.

    The platform initially advances the entry cost.  With ``bear_now=True``
    that advance is immediately recognized as the platform's replacement
    cost rather than charged to the customer.
    """
    ensure_schema(db)
    with tx(db):
        purchase = one(db, "SELECT * FROM rs_purchases WHERE purchase_id=?",
                       (purchase_id,))
        if not purchase:
            return {"decision": "unknown_purchase"}
        if not backup_host or backup_host == purchase["host"] or valid_days <= 0:
            return {"decision": "invalid_backup_entry"}
        if one(db, "SELECT entitlement_id FROM rs_entitlements WHERE entitlement_id=?",
               (f"ent-alt-{backup_id}",)):
            return {"decision": "backup_entry_exists"}

        valid_from = at if valid_from is None else valid_from
        valid_to = valid_from + valid_days
        advance_id = advance_id or f"adv-backup-{backup_id}"
        notice_id = notice_id or f"notice-{backup_id}"

        _post_entry(db, f"je-advance-{advance_id}", at, "platform_advance", [
            {"account": "platform_advance_receivable", "debit": cost_cents},
            {"account": "platform_available_cash", "credit": cost_cents},
        ], purchase_id=purchase_id)
        db.execute(
            "INSERT INTO rs_advances(advance_id,purchase_id,amount_cents,purpose,"
            "counterparty_id,status,created_at,expense_account,note) "
            "VALUES(?,?,?, 'backup_entry',?, 'outstanding', ?,?,?)",
            (advance_id, purchase_id, cost_cents, provider_id, at,
             "alternative entry and migration access", None),
        )

        db.execute(
            "INSERT INTO rs_entitlements(entitlement_id,purchase_id,host,customer_id,"
            "mandate_id,kind,status,valid_from,valid_to,backup_host,"
            "funding_advance_id,source_ref,created_at) "
            "VALUES(?,?,?,?,?, 'alternative','active',?,?,?,?,?,?)",
            (f"ent-alt-{backup_id}", purchase_id, purchase["host"],
             purchase["customer_id"], purchase["mandate_id"], valid_from, valid_to,
             backup_host, advance_id, f"backup:{backup_id}", at),
        )
        message = (f"Migrate {purchase['host']} traffic to temporary entry "
                   f"{backup_host} by {valid_to}; platform bears entry cost.")
        db.execute(
            "INSERT INTO rs_notices(notice_id,purchase_id,kind,old_host,backup_host,"
            "agent_id,status,message,issued_at) "
            "VALUES(?,?, 'migration',?,?,?, 'issued', ?,?)",
            (notice_id, purchase_id, purchase["host"], backup_host,
             purchase["agent_id"], message, at),
        )

        result_status = "backup_entry_secured"
        if bear_now:
            _post_entry(db, f"je-advance-bear-{advance_id}", at,
                        "platform_bears_advance", [
                {"account": "alternative_entry_expense", "debit": cost_cents},
                {"account": "platform_advance_receivable", "credit": cost_cents},
            ], purchase_id=purchase_id)
            db.execute(
                "UPDATE rs_advances SET status='borne_by_platform',resolved_at=?,"
                "expense_account='alternative_entry_expense' WHERE advance_id=?",
                (at, advance_id),
            )
            result_status = "backup_entry_secured_cost_borne"

        db.execute("UPDATE rs_purchases SET status='alternative_secured',updated_at=? "
                   "WHERE purchase_id=?", (at, purchase_id))
        return {"decision": result_status, "backup_entitlement_id": f"ent-alt-{backup_id}",
                "notice_id": notice_id, "advance_id": advance_id,
                "valid_from": valid_from, "valid_to": valid_to,
                "cost_cents": cost_cents}


def pay_bill(db, bill_id, at, payment_ref, *, entry_id=None):
    """Settle a registrar, agent, or other payable from platform cash."""
    ensure_schema(db)
    with tx(db):
        bill = one(db, "SELECT * FROM rs_bills WHERE bill_id=?", (bill_id,))
        if not bill:
            return {"decision": "unknown_bill"}
        if bill["status"] == "paid":
            return {"decision": "bill_already_paid", "bill_id": bill_id}
        if bill["kind"] == "customer_invoice":
            return {"decision": "use_payment_settlement_for_customer_invoice"}

        entry_id = entry_id or f"je-pay-{bill_id}"
        _post_entry(db, entry_id, at, f"pay_{bill['kind']}", [
            {"account": bill["account"], "debit": bill["amount_cents"],
             "party_id": bill["party_id"]},
            {"account": "platform_available_cash", "credit": bill["amount_cents"]},
        ], purchase_id=bill["purchase_id"], description=payment_ref)
        db.execute(
            "UPDATE rs_bills SET status='paid',settled_at=?,external_ref=? WHERE bill_id=?",
            (at, payment_ref, bill_id),
        )
        return {"decision": "bill_paid", "bill_id": bill_id,
                "amount_cents": bill["amount_cents"]}


def entitlement(db, purchase_id, kind="registered"):
    return one(
        db,
        "SELECT * FROM rs_entitlements WHERE purchase_id=? AND kind=? "
        "ORDER BY created_at DESC LIMIT 1",
        (purchase_id, kind),
    )


def settlement_distribution(db, purchase_id):
    """Per-purchase split and traceable open/paid settlement balances."""
    purchase = one(db, "SELECT * FROM rs_purchases WHERE purchase_id=?", (purchase_id,))
    if not purchase:
        return None

    def bill(bill_id):
        row = one(db, "SELECT * FROM rs_bills WHERE bill_id=?", (bill_id,))
        return dict(row) if row else None

    registrar_bill = bill(f"bill-registrar-{purchase_id}")
    commission_bill = bill(f"bill-commission-{purchase_id}")
    payments = rows(db, "SELECT status, amount_cents FROM rs_payments WHERE purchase_id=?",
                   (purchase_id,))
    advances = rows(db, "SELECT status, amount_cents FROM rs_advances WHERE purchase_id=?",
                    (purchase_id,))

    def payment_sum(status):
        return sum(p["amount_cents"] for p in payments if p["status"] == status)

    return {
        "purchase_id": purchase_id,
        "customer_invoice_cents": purchase["price_cents"],
        "registrar_fee_cents": purchase["registrar_fee_cents"],
        "agent_commission_cents": purchase["commission_cents"],
        "platform_margin_cents": (purchase["price_cents"]
                                 - purchase["registrar_fee_cents"]
                                 - purchase["commission_cents"]),
        "customer_settled_cents": payment_sum("settled"),
        "customer_authorized_hold_cents": payment_sum("authorized"),
        "customer_refunded_cents": payment_sum("refunded"),
        "customer_bank_returned_cents": payment_sum("returned"),
        "registrar_open_cents": (registrar_bill["amount_cents"]
                                 if registrar_bill and registrar_bill["status"] == "open" else 0),
        "registrar_paid_cents": (registrar_bill["amount_cents"]
                                 if registrar_bill and registrar_bill["status"] == "paid" else 0),
        "commission_agent_id": purchase["agent_id"],
        "commission_open_cents": (commission_bill["amount_cents"]
                                  if commission_bill and commission_bill["status"] == "open" else 0),
        "commission_paid_cents": (commission_bill["amount_cents"]
                                  if commission_bill and commission_bill["status"] == "paid" else 0),
        "platform_deposit_locked_cents": account_balance(
            db, "guarantee_deposit_locked", purchase_id=purchase_id),
        "platform_advance_outstanding_cents": sum(
            a["amount_cents"] for a in advances if a["status"] == "outstanding"),
        "platform_advance_borne_cents": sum(
            a["amount_cents"] for a in advances if a["status"] == "borne_by_platform"),
    }


def purchase_statement(db, purchase_id):
    """Return all traceable records for one renewal purchase."""
    ensure_schema(db)
    purchase = one(db, "SELECT * FROM rs_purchases WHERE purchase_id=?", (purchase_id,))
    if not purchase:
        return None
    return {
        "purchase": purchase,
        "mandate": one(db, "SELECT * FROM rs_mandates WHERE mandate_id=?",
                       (purchase["mandate_id"],)),
        "submissions": rows(db,
            "SELECT * FROM rs_submissions WHERE purchase_id=? ORDER BY submitted_at",
            (purchase_id,)),
        "receipts": rows(db,
            "SELECT * FROM rs_registry_receipts WHERE purchase_id=? ORDER BY received_at",
            (purchase_id,)),
        "entitlements": rows(db,
            "SELECT * FROM rs_entitlements WHERE purchase_id=? ORDER BY created_at",
            (purchase_id,)),
        "payments": rows(db,
            "SELECT * FROM rs_payments WHERE purchase_id=? ORDER BY authorized_at",
            (purchase_id,)),
        "bills": rows(db, "SELECT * FROM rs_bills WHERE purchase_id=? ORDER BY issued_at",
                      (purchase_id,)),
        "advances": rows(db, "SELECT * FROM rs_advances WHERE purchase_id=? ORDER BY created_at",
                         (purchase_id,)),
        "notices": rows(db, "SELECT * FROM rs_notices WHERE purchase_id=? ORDER BY issued_at",
                        (purchase_id,)),
        "purchase_account_balances": {
            root: account_balance(db, account, purchase_id=purchase_id)
            for account, root in [
                ("customer_receivable:" + purchase["customer_id"], "customer_receivable"),
                ("customer_overpayment:" + purchase["customer_id"], "customer_overpayment"),
                ("guarantee_deposit_locked", "guarantee_deposit_locked"),
                ("platform_advance_receivable", "platform_advance_receivable"),
            ]
        },
    }


def run(db, command):
    """Small idempotent command dispatcher for stores that use request IDs."""
    ensure_schema(db)
    request_id = command.get("request_id")
    if request_id:
        old = one(db, "SELECT * FROM rs_commands WHERE request_id=?", (request_id,))
        if old:
            import json
            if json.loads(old["input_json"]) != command:
                return {"decision": "request_conflict"}
            return json.loads(old["result_json"])

    op = command.get("op")
    allowed = {
        "sign_mandate": sign_mandate,
        "change_agent": change_agent,
        "open_renewal": open_renewal,
        "authorize_payment": authorize_payment,
        "settle_payment": settle_payment,
        "revoke_authorization": revoke_authorization,
        "refund_payment": refund_payment,
        "return_payment": return_payment,
        "cancel_customer_invoice": cancel_customer_invoice,
        "submit_to_registrar": submit_to_registrar,
        "confirm_registry_receipt": confirm_registry_receipt,
        "issue_guaranteed_promise": issue_guaranteed_promise,
        "record_promise_breach": record_promise_breach,
        "award_compensation": award_compensation,
        "secure_backup_entry": secure_backup_entry,
        "pay_bill": pay_bill,
        "advance_platform_funds": advance_platform_funds,
        "recover_platform_advance": recover_platform_advance,
        "bear_platform_advance": bear_platform_advance,
        "release_guarantee_deposit": release_guarantee_deposit,
        "reassign_order_agent": reassign_order_agent,
        "settlement_distribution": settlement_distribution,
    }
    func = allowed.get(op)
    if func is None:
        return {"decision": "unknown_op"}

    fields = {k: v for k, v in command.items() if k not in ("request_id", "op")}
    result = func(db, **fields)

    if request_id:
        import json
        with tx(db):
            db.execute(
                "INSERT OR IGNORE INTO rs_commands(request_id,op,input_json,result_json,at) "
                "VALUES(?,?,?,?,?)",
                (request_id, op, json.dumps(command, sort_keys=True),
                 json.dumps(result, sort_keys=True), command.get("at", 0)),
            )
    return result
