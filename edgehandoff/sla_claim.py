"""Provisional customer service credit claim."""
from .store import one


def draft(db, claim_id, plan_id, cents_per_minute):
    db.execute('CREATE TABLE IF NOT EXISTS sla_claims(id TEXT PRIMARY KEY, plan_id TEXT, amount INTEGER, status TEXT)')
    old=one(db,'SELECT * FROM sla_claims WHERE id=?',(claim_id,))
    if old:return {'decision':'reused','amount':old['amount']}
    plan=one(db,'SELECT * FROM plans WHERE id=?',(plan_id,))
    if not plan or cents_per_minute<0:return {'decision':'unavailable'}
    n=db.execute('SELECT count(*) FROM samples WHERE plan_id=? AND healthy=0',(plan_id,)).fetchone()[0]
    amount=n*cents_per_minute
    db.execute('INSERT INTO sla_claims VALUES(?,?,?,?)',(claim_id,plan_id,amount,'draft'))
    return {'decision':'drafted','amount':amount}
