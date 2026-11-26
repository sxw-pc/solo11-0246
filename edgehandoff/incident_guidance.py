"""Customer-actionable guidance for an ingress rollback incident.

A rollback recorded 'done' on the console does not mean customer traffic is
consistent: the new backend may have accepted requests before the rollback
and payment callbacks can keep arriving at the old endpoint afterwards.
This module turns raw evidence — backend acceptance records, payment
provider callbacks, proxy trace segments and trace gaps — into per-tenant
action notices, instead of deriving statements from console state or from
plan.host mass mail.

Policy encoded here:

* Targeted 'continue' requires direct evidence: every known request of the
  tenant is matched by a backend acceptance or a bank-verified payment, no
  payment callback is left unverified, and no request stays unresolved next
  to a proxy trace gap (a failed request followed by a gap may have been
  retried invisibly, so it is unverified — never 'safe to retry').
* A broader action order is required whenever the window contains traffic
  that cannot be attributed to a tenant: the affected set is then unknown,
  every contracted tenant gets the same generic pause instruction, and
  targeted 'continue' notices are refused until attribution is complete.
* Recipients come from contract contacts authorised at the incident
  reference time — never inferred from domain holders — and a notice counts
  as sent only with an actual channel receipt; bounces escalate to the
  contracted backup contact.
* Issued notices are never rewritten. Evidence learned later (late payment
  callbacks, trace backfill, bank verification) yields a new version whose
  correction note carries the learned-at times, so a previously 'pending
  verification' statement can never masquerade as known at the time.
"""
import json

from .store import one, rows

CONTINUE = 'continue_confirmed'
PAUSE = 'pause_payment'
RETRY = 'retry_failed'
BROAD = 'pause_all_unverified'

INSTRUCTION_TEXT = {
    CONTINUE: '已确认或已核实的项目请勿重复提交或重复支付；其余操作可继续正常进行。',
    PAUSE: '暂停提交新的支付，请勿重放未确认的订单；在银行核实完成前不要重复付款。',
    RETRY: '上述未生效请求确认未被处理，可安全重新提交。',
    BROAD: '请暂停所有支付提交与订单重放，等待定向核实通知。',
}

EVIDENCE_KINDS = ('acceptance', 'payment_callback', 'payment_verified', 'request', 'trace_gap')
KIND_LABEL = {
    'acceptance': '后端接受记录',
    'payment_callback': '支付回调',
    'payment_verified': '支付核实',
    'request': '请求追踪',
    'trace_gap': '追踪缺口',
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS incident_contacts(
  tenant TEXT, contact TEXT, channel TEXT, role TEXT,
  valid_from INTEGER, valid_until INTEGER,
  PRIMARY KEY(tenant, role, contact));
CREATE TABLE IF NOT EXISTS incident_evidence(
  id TEXT PRIMARY KEY, tenant TEXT, kind TEXT,
  at INTEGER, end_at INTEGER, learned_at INTEGER, detail TEXT);
CREATE TABLE IF NOT EXISTS incident_notices(
  id TEXT PRIMARY KEY, incident TEXT, tenant TEXT, version INTEGER,
  instruction TEXT, body TEXT, facts TEXT,
  window_start INTEGER, window_end INTEGER, reference_at INTEGER,
  issued_at INTEGER, next_update INTEGER, status TEXT);
CREATE TABLE IF NOT EXISTS incident_notice_recipients(
  notice TEXT, contact TEXT, channel TEXT, role TEXT,
  PRIMARY KEY(notice, contact));
CREATE TABLE IF NOT EXISTS incident_deliveries(
  notice TEXT, contact TEXT, outcome TEXT, receipt TEXT, at INTEGER,
  PRIMARY KEY(notice, contact));
CREATE TABLE IF NOT EXISTS incident_notice_links(
  notice TEXT PRIMARY KEY, supersedes TEXT);
"""


def _ensure(db):
    db.executescript(SCHEMA)


def _fmt(t):
    return '%02d:%02d' % (t // 60, t % 60)


def _span(s, e):
    return _fmt(s) if s == e else '%s-%s' % (_fmt(s), _fmt(e))


def register_contact(db, tenant, contact, channel, role, valid_from, valid_until):
    """Register a contract contact with its authorisation window."""
    _ensure(db)
    if role not in ('primary', 'backup') or valid_until < valid_from:
        return {'decision': 'invalid_contact'}
    old = one(db, 'SELECT * FROM incident_contacts WHERE tenant=? AND role=? AND contact=?',
              (tenant, role, contact))
    if old:
        same = (old['channel'], old['valid_from'], old['valid_until']) == (channel, valid_from, valid_until)
        return {'decision': 'reused'} if same else {'decision': 'contact_conflict'}
    db.execute('INSERT INTO incident_contacts VALUES(?,?,?,?,?,?)',
               (tenant, contact, channel, role, valid_from, valid_until))
    return {'decision': 'registered'}


def add_evidence(db, evidence_id, tenant, kind, at, learned_at, end_at=None, detail=''):
    """Record raw evidence; learned_at may be later than at (late callbacks, backfill)."""
    _ensure(db)
    if kind not in EVIDENCE_KINDS:
        return {'decision': 'unknown_kind'}
    if learned_at < at:
        return {'decision': 'invalid_evidence'}
    if kind == 'trace_gap':
        tenant = ''
        if end_at is None or end_at < at:
            return {'decision': 'invalid_evidence'}
    else:
        end_at = at
    tenant = tenant or ''
    old = one(db, 'SELECT * FROM incident_evidence WHERE id=?', (evidence_id,))
    if old:
        same = (old['tenant'], old['kind'], old['at'], old['end_at'], old['learned_at'], old['detail']) == \
               (tenant, kind, at, end_at, learned_at, detail)
        return {'decision': 'reused'} if same else {'decision': 'evidence_conflict'}
    db.execute('INSERT INTO incident_evidence VALUES(?,?,?,?,?,?,?)',
               (evidence_id, tenant, kind, at, end_at, learned_at, detail))
    return {'decision': 'recorded'}


def _overlap(e, ws, we):
    return e['at'] <= we and e['end_at'] >= ws


def _merge(intervals):
    out = []
    for s, e in sorted(intervals):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def _assess(db, tenant, ws, we, at):
    """Classify a tenant from evidence learned up to `at` (never from console state)."""
    known = rows(db, 'SELECT * FROM incident_evidence WHERE learned_at<=? ORDER BY at,id', (at,))
    gaps = [e for e in known if e['kind'] == 'trace_gap' and _overlap(e, ws, we)]
    mine = [e for e in known if e['tenant'] == tenant and _overlap(e, ws, we)]
    accepts = [e for e in mine if e['kind'] == 'acceptance']
    accepted = {a['detail'] for a in accepts}
    verified = {e['detail'] for e in known if e['kind'] == 'payment_verified' and e['tenant'] == tenant}
    callbacks = [e for e in mine if e['kind'] == 'payment_callback']
    requests = [e for e in mine if e['kind'] == 'request']
    unverified = [c for c in callbacks if c['detail'] not in verified]
    for r in requests:
        if r['detail'] in accepted or r['detail'] in verified:
            continue
        # unresolved request inside a gap, or followed by a gap (possible
        # invisible retry): cannot be called failed, must stay unverified
        if any(g['end_at'] >= r['at'] for g in gaps):
            unverified.append(r)
    unv_ids = {e['id'] for e in unverified}
    failed = [r for r in requests
              if r['detail'] not in accepted and r['detail'] not in verified and r['id'] not in unv_ids]
    intervals = []
    for e in unverified:
        if e['kind'] == 'request':
            g = next((g for g in gaps if g['at'] <= e['at'] <= g['end_at']), None)
            if g is None:
                g = min((g for g in gaps if g['end_at'] >= e['at']), key=lambda g: g['at'], default=None)
            intervals.append((max(g['at'], ws), min(g['end_at'], we)) if g else (e['at'], e['at']))
        else:
            intervals.append((e['at'], e['at']))
    intervals = _merge(intervals)
    if unverified:
        classification, instruction = 'unverified', PAUSE
    elif accepts or verified:
        classification, instruction = 'confirmed', CONTINUE
    elif failed:
        classification, instruction = 'failed', RETRY
    else:
        classification, instruction = 'no_activity', None
    verified_pay = sorted(verified & {c['detail'] for c in callbacks})
    facts = (instruction, tuple(sorted(accepted)), tuple(sorted(verified)),
             tuple(sorted(unv_ids)), tuple(intervals))
    return {'classification': classification, 'instruction': instruction,
            'accepts': accepts, 'verified_pay': verified_pay, 'unverified': unverified,
            'intervals': intervals, 'failed': failed, 'facts': facts}


def _broad_required(db, ws, we, at):
    """Unattributed traffic in the window means the affected set is unknown."""
    return one(db, "SELECT id FROM incident_evidence WHERE tenant='' AND kind IN ('request','payment_callback')"
                   ' AND learned_at<=? AND at<=? AND end_at>=?', (at, we, ws)) is not None


def recommend(db, window_start, window_end, at):
    """Per-tenant instructions plus whether a broad action order is required."""
    _ensure(db)
    known = rows(db, 'SELECT * FROM incident_evidence WHERE learned_at<=?', (at,))
    tenants = sorted({e['tenant'] for e in known if e['tenant'] and _overlap(e, window_start, window_end)})
    instructions = {}
    for t in tenants:
        a = _assess(db, t, window_start, window_end, at)
        if a['classification'] != 'no_activity':
            instructions[t] = a['instruction']
    broad = _broad_required(db, window_start, window_end, at)
    result = {'tenants': instructions, 'broad_required': broad}
    if broad:
        result['reason'] = 'unattributed_activity'
    return result


def _body(incident, tenant, version, a, next_update, correction=None):
    lines = ['事件 %s 客户行动通知（第 %d 版）' % (incident, version)]
    if correction:
        lines.append(correction)
    if a['accepts']:
        ids = '、'.join(sorted({x['detail'] for x in a['accepts']}))
        s = min(x['at'] for x in a['accepts'])
        e = max(x['at'] for x in a['accepts'])
        lines.append('可确认接受窗口： %s，后端已确认接受 %d 笔： %s。' % (_span(s, e), len(a['accepts']), ids))
    else:
        lines.append('可确认接受窗口： 无已确认的后端接受。')
    if a['verified_pay']:
        lines.append('已核实支付： %s（支付商与银行核实）。' % '、'.join(a['verified_pay']))
    if a['intervals']:
        spans = '、'.join(_span(s, e) for s, e in a['intervals'])
        lines.append('未核实区间： %s；此期间的请求与支付状态尚未核实。' % spans)
    else:
        lines.append('未核实区间： 无。')
    if a['unverified']:
        ids = '、'.join(sorted({x['detail'] for x in a['unverified']}))
        lines.append('待核实项目： %s。' % ids)
    if a['failed']:
        ids = '、'.join(sorted({x['detail'] for x in a['failed']}))
        lines.append('未生效请求： %s。' % ids)
    lines.append('行动指令： ' + INSTRUCTION_TEXT[a['instruction']])
    lines.append('下次更新： 不晚于 %s。' % _fmt(next_update))
    return '\n'.join(lines)


def draft(db, notice_id, incident, tenant, window_start, window_end, reference_at, at, next_update):
    """Draft a per-tenant notice from evidence known at `at`.

    reference_at pins recipient resolution to the incident-time contact
    authorisation; next_update is the committed time of the next bulletin.
    """
    _ensure(db)
    if one(db, 'SELECT id FROM incident_notices WHERE id=?', (notice_id,)):
        return {'decision': 'reused'}
    if window_start > window_end or reference_at > at or next_update <= at:
        return {'decision': 'invalid_schedule'}
    a = _assess(db, tenant, window_start, window_end, at)
    if a['classification'] == 'no_activity':
        return {'decision': 'no_activity'}
    if a['instruction'] == CONTINUE and _broad_required(db, window_start, window_end, at):
        return {'decision': 'broad_order_required'}
    body = _body(incident, tenant, 1, a, next_update)
    db.execute('INSERT INTO incident_notices VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (notice_id, incident, tenant, 1, a['instruction'], body, json.dumps(a['facts']),
                window_start, window_end, reference_at, None, next_update, 'draft'))
    return {'decision': 'drafted', 'instruction': a['instruction'], 'classification': a['classification']}


def draft_broadcast(db, notice_id, incident, window_start, window_end, reference_at, at, next_update):
    """Draft the broad action order: identical generic pause for every tenant.

    The body carries no tenant-specific transactions, so a shared bulletin
    cannot leak one tenant's orders or payments to another.
    """
    _ensure(db)
    if one(db, 'SELECT id FROM incident_notices WHERE id=?', (notice_id,)):
        return {'decision': 'reused'}
    if window_start > window_end or reference_at > at or next_update <= at:
        return {'decision': 'invalid_schedule'}
    body = '\n'.join([
        '事件 %s 客户行动通知（第 1 版）' % incident,
        '影响窗口： %s，入口切换已回滚，部分请求与支付状态正在核实。' % _span(window_start, window_end),
        '行动指令： ' + INSTRUCTION_TEXT[BROAD],
        '下次更新： 不晚于 %s。' % _fmt(next_update)])
    db.execute('INSERT INTO incident_notices VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (notice_id, incident, '', 1, BROAD, body, json.dumps([]),
                window_start, window_end, reference_at, None, next_update, 'draft'))
    return {'decision': 'drafted', 'instruction': BROAD}


def _authorized(db, tenant, reference_at, role):
    sql = 'SELECT * FROM incident_contacts WHERE role=? AND valid_from<=? AND valid_until>=?'
    args = [role, reference_at, reference_at]
    if tenant is not None:
        sql += ' AND tenant=?'
        args.append(tenant)
    return rows(db, sql + ' ORDER BY contact', args)


def issue(db, notice_id, at):
    """Issue a draft: resolve recipients from incident-time authorisation.

    A per-tenant draft whose facts were overtaken by later-learned evidence
    is refused as stale — re-draft or correct instead of editing in place.
    """
    _ensure(db)
    n = one(db, 'SELECT * FROM incident_notices WHERE id=?', (notice_id,))
    if not n:
        return {'decision': 'unknown_notice'}
    if n['status'] != 'draft':
        return {'decision': 'already_issued'}
    if n['tenant']:
        a = _assess(db, n['tenant'], n['window_start'], n['window_end'], at)
        if json.dumps(a['facts']) != n['facts']:
            return {'decision': 'stale_draft'}
        contacts = _authorized(db, n['tenant'], n['reference_at'], 'primary')
    else:
        contacts = _authorized(db, None, n['reference_at'], 'primary')
    if not contacts:
        return {'decision': 'no_authorized_contact'}
    for c in contacts:
        db.execute('INSERT OR IGNORE INTO incident_notice_recipients VALUES(?,?,?,?)',
                   (notice_id, c['contact'], c['channel'], c['role']))
    db.execute("UPDATE incident_notices SET status='issued',issued_at=? WHERE id=?", (at, notice_id))
    return {'decision': 'issued', 'recipients': [c['contact'] for c in contacts]}


def _tenant_of(db, contact):
    r = one(db, 'SELECT tenant FROM incident_contacts WHERE contact=? ORDER BY tenant', (contact,))
    return r['tenant'] if r else None


def record_delivery(db, notice_id, contact, outcome, at, receipt=None):
    """Record a channel outcome for a recipient.

    'delivered' requires the channel's actual receipt — a mail interface
    returning success is not delivery. A bounce escalates to the contracted
    backup contact authorised at the incident reference time.
    """
    _ensure(db)
    n = one(db, 'SELECT * FROM incident_notices WHERE id=?', (notice_id,))
    if not n or n['status'] == 'draft':
        return {'decision': 'not_issued'}
    r = one(db, 'SELECT * FROM incident_notice_recipients WHERE notice=? AND contact=?', (notice_id, contact))
    if not r:
        return {'decision': 'not_a_recipient'}
    if one(db, 'SELECT * FROM incident_deliveries WHERE notice=? AND contact=?', (notice_id, contact)):
        return {'decision': 'duplicate_delivery'}
    if outcome == 'delivered':
        if not receipt:
            return {'decision': 'receipt_required'}
        db.execute('INSERT INTO incident_deliveries VALUES(?,?,?,?,?)',
                   (notice_id, contact, 'delivered', receipt, at))
        db.execute("UPDATE incident_notices SET status='delivered' WHERE id=?", (notice_id,))
        return {'decision': 'delivered'}
    if outcome == 'bounced':
        db.execute('INSERT INTO incident_deliveries VALUES(?,?,?,?,?)',
                   (notice_id, contact, 'bounced', None, at))
        tenant = n['tenant'] or _tenant_of(db, contact)
        backups = _authorized(db, tenant, n['reference_at'], 'backup') if tenant else []
        existing = {x['contact'] for x in rows(db, 'SELECT contact FROM incident_notice_recipients WHERE notice=?',
                                               (notice_id,))}
        new = [b for b in backups if b['contact'] not in existing]
        for b in new:
            db.execute('INSERT INTO incident_notice_recipients VALUES(?,?,?,?)',
                       (notice_id, b['contact'], b['channel'], 'backup'))
        if new:
            return {'decision': 'escalated', 'backup': new[0]['contact']}
        recipients = rows(db, 'SELECT contact FROM incident_notice_recipients WHERE notice=?', (notice_id,))
        bounced = {x['contact'] for x in rows(db, "SELECT contact FROM incident_deliveries"
                                                  " WHERE notice=? AND outcome='bounced'", (notice_id,))}
        if all(x['contact'] in bounced for x in recipients):
            db.execute("UPDATE incident_notices SET status='undeliverable' WHERE id=?", (notice_id,))
        return {'decision': 'escalation_unavailable'}
    return {'decision': 'unknown_outcome'}


def _correction_note(old, new_evidence):
    labels = []
    for e in new_evidence:
        label = '%s（%s 获知）' % (KIND_LABEL[e['kind']], _fmt(e['learned_at']))
        if label not in labels:
            labels.append(label)
    return ('更正说明： 本版替代第 %d 版（发布于 %s，该版原文保持不变，其“待核实”为发布当时的状态）。'
            '发布后新获知： %s。' % (old['version'], _fmt(old['issued_at']), '；'.join(labels)))


def correct(db, new_notice_id, supersedes, at, next_update):
    """Draft the next version of an issued notice from later-learned evidence.

    The superseded notice is never edited; the chain is linear, and the
    correction note discloses when each piece of new evidence was learned,
    so a late callback cannot be presented as known at the original time.
    """
    _ensure(db)
    old = one(db, 'SELECT * FROM incident_notices WHERE id=?', (supersedes,))
    if not old:
        return {'decision': 'unknown_notice'}
    if old['status'] == 'draft':
        return {'decision': 'not_issued'}
    if not old['tenant']:
        return {'decision': 'broadcast_not_correctable'}
    if one(db, 'SELECT id FROM incident_notices WHERE id=?', (new_notice_id,)):
        return {'decision': 'reused'}
    if one(db, 'SELECT notice FROM incident_notice_links WHERE supersedes=?', (supersedes,)):
        return {'decision': 'already_corrected'}
    if next_update <= at:
        return {'decision': 'invalid_schedule'}
    new_evidence = rows(db, 'SELECT * FROM incident_evidence WHERE learned_at>? AND learned_at<=?'
                            " AND (tenant=? OR kind='trace_gap') ORDER BY learned_at,id",
                        (old['issued_at'], at, old['tenant']))
    if not new_evidence:
        return {'decision': 'no_new_evidence'}
    a = _assess(db, old['tenant'], old['window_start'], old['window_end'], at)
    if json.dumps(a['facts']) == old['facts']:
        return {'decision': 'no_change'}
    body = _body(old['incident'], old['tenant'], old['version'] + 1, a, next_update,
                 correction=_correction_note(old, new_evidence))
    db.execute('INSERT INTO incident_notices VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (new_notice_id, old['incident'], old['tenant'], old['version'] + 1, a['instruction'], body,
                json.dumps(a['facts']), old['window_start'], old['window_end'], old['reference_at'],
                None, next_update, 'draft'))
    db.execute('INSERT INTO incident_notice_links VALUES(?,?)', (new_notice_id, supersedes))
    return {'decision': 'correction_drafted', 'version': old['version'] + 1, 'instruction': a['instruction']}
