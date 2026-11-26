import json, sqlite3
from contextlib import contextmanager

SCHEMA="""
CREATE TABLE IF NOT EXISTS claims(host TEXT PRIMARY KEY,holder TEXT,epoch INTEGER,lease_until INTEGER,challenge TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS proofs(host TEXT,epoch INTEGER,challenge TEXT,at INTEGER,PRIMARY KEY(host,epoch));
CREATE TABLE IF NOT EXISTS delegations(id TEXT PRIMARY KEY,host TEXT,grantee TEXT,scope TEXT,until_ts INTEGER,revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,owner TEXT,status TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS order_names(order_id TEXT,host TEXT,epoch INTEGER,PRIMARY KEY(order_id,host));
CREATE TABLE IF NOT EXISTS certificates(serial TEXT PRIMARY KEY,order_id TEXT,not_before INTEGER,expires INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS renewals(predecessor TEXT PRIMARY KEY,successor TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS gateways(id TEXT PRIMARY KEY,epoch INTEGER);
CREATE TABLE IF NOT EXISTS deployments(id TEXT PRIMARY KEY,serial TEXT,gateway TEXT,gateway_epoch INTEGER,at INTEGER);
CREATE TABLE IF NOT EXISTS backends(id TEXT PRIMARY KEY,healthy INTEGER,epoch INTEGER);
CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY,host TEXT,claim_epoch INTEGER,serial TEXT,gateway TEXT,old_backend TEXT,new_backend TEXT,old_epoch INTEGER,new_epoch INTEGER,stage INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS samples(id TEXT PRIMARY KEY,plan_id TEXT,stage INTEGER,at INTEGER,healthy INTEGER);
CREATE TABLE IF NOT EXISTS rollbacks(id TEXT PRIMARY KEY,plan_id TEXT,at INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS service_windows(id TEXT PRIMARY KEY,merchant TEXT,start_ts INTEGER,end_ts INTEGER);
CREATE TABLE IF NOT EXISTS ingress_requests(request_id TEXT PRIMARY KEY,merchant TEXT,order_no TEXT,at INTEGER,retries_of TEXT);
CREATE TABLE IF NOT EXISTS gateway_receipts(receipt_id TEXT PRIMARY KEY,request_id TEXT,accepted INTEGER,at INTEGER);
CREATE TABLE IF NOT EXISTS cashier_confirmations(confirmation_id TEXT PRIMARY KEY,merchant TEXT,order_no TEXT,success INTEGER,at INTEGER);
CREATE TABLE IF NOT EXISTS purchase_replays(replay_id TEXT PRIMARY KEY,merchant TEXT,order_no TEXT,success INTEGER,clearing_no TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS bank_clearing(clearing_no TEXT PRIMARY KEY,merchant TEXT,order_no TEXT,paid INTEGER,bounced INTEGER,at INTEGER);
CREATE TABLE IF NOT EXISTS refunds(refund_id TEXT PRIMARY KEY,merchant TEXT,order_no TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS merchant_accounts(merchant TEXT PRIMARY KEY,account_no TEXT,status TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS account_changes(change_id TEXT PRIMARY KEY,merchant TEXT,old_account TEXT,new_account TEXT,reason TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS sla_cases(case_id TEXT PRIMARY KEY,merchant TEXT,window_id TEXT,plan_id TEXT,unit_cents INTEGER,mode TEXT,status TEXT,opened_at INTEGER);
CREATE TABLE IF NOT EXISTS claim_items(id TEXT PRIMARY KEY,case_id TEXT,order_no TEXT,canonical_request TEXT,attempts INTEGER,accepted_in_window INTEGER,status TEXT,basis TEXT,amount_cents INTEGER,updated_at INTEGER);
CREATE TABLE IF NOT EXISTS preservation_commitments(commitment_id TEXT PRIMARY KEY,case_id TEXT,cap_cents INTEGER,signed_at INTEGER);
CREATE TABLE IF NOT EXISTS invoices(invoice_no TEXT PRIMARY KEY,case_id TEXT,period TEXT,amount_cents INTEGER,mode TEXT,issued_at INTEGER);
CREATE TABLE IF NOT EXISTS bank_payments(bank_ref TEXT PRIMARY KEY,entry_id TEXT,account_no TEXT,amount_cents INTEGER,direction TEXT,status TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS ledger_entries(entry_id TEXT PRIMARY KEY,case_id TEXT,request_id TEXT,order_no TEXT,kind TEXT,amount_cents INTEGER,merchant_delta INTEGER,gl_account TEXT,gl_delta INTEGER,period TEXT,origin_entry TEXT,origin_invoice TEXT,bank_ref TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,subsystem TEXT,request_id TEXT UNIQUE,input TEXT,result TEXT);
"""

def connect(path):
    db=sqlite3.connect(path,isolation_level=None)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA busy_timeout=3000')
    db.executescript(SCHEMA)
    return db

@contextmanager
def tx(db):
    db.execute('BEGIN IMMEDIATE')
    try:
        yield
        db.execute('COMMIT')
    except BaseException:
        db.execute('ROLLBACK')
        raise

def one(db,sql,args=()):
    row=db.execute(sql,args).fetchone()
    return dict(row) if row else None

def rows(db,sql,args=()):return [dict(r) for r in db.execute(sql,args)]

def execute(db,subsystem,step):
    from . import ownership,certificate,cutover,sla_settlement
    module={'ownership':ownership,'certificate':certificate,'cutover':cutover,'settlement':sla_settlement}[subsystem]
    with tx(db):
        old=one(db,'SELECT * FROM events WHERE request_id=?',(step['request_id'],))
        if old:
            if json.loads(old['input'])!=step or old['subsystem']!=subsystem:return {'decision':'request_conflict'}
            return json.loads(old['result'])
        result=module.run(db,step)
        db.execute('INSERT INTO events(subsystem,request_id,input,result) VALUES(?,?,?,?)',
                   (subsystem,step['request_id'],json.dumps(step,sort_keys=True),json.dumps(result,sort_keys=True)))
        return result

def replay(path):
    source=connect(path); target=connect(':memory:')
    original=rows(source,'SELECT subsystem,input,result FROM events ORDER BY seq')
    divergence=[]
    for i,item in enumerate(original,1):
        actual=execute(target,item['subsystem'],json.loads(item['input']))
        if actual!=json.loads(item['result']):divergence.append({'event':i,'kind':'decision'})
    tables=[r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('events','sqlite_sequence') ORDER BY name")]
    for table in tables:
        if [tuple(r) for r in source.execute(f'SELECT * FROM {table} ORDER BY rowid')]!=[tuple(r) for r in target.execute(f'SELECT * FROM {table} ORDER BY rowid')]:
            divergence.append({'table':table,'kind':'state'})
    source.close();target.close()
    return {'verified':not divergence,'events':len(original),'divergence':divergence}
