"""Draft customer notice after a cutover rollback."""
from .store import one


def draft(db, notice_id, rollback_id):
    db.execute('CREATE TABLE IF NOT EXISTS client_notices(id TEXT PRIMARY KEY, rollback TEXT, host TEXT, status TEXT)')
    old=one(db,'SELECT * FROM client_notices WHERE id=?',(notice_id,))
    if old:return {'decision':'reused'}
    rollback=one(db,'SELECT * FROM rollbacks WHERE id=?',(rollback_id,))
    plan=one(db,'SELECT * FROM plans WHERE id=?',(rollback['plan_id'],)) if rollback else None
    if not plan:return {'decision':'unavailable'}
    db.execute('INSERT INTO client_notices VALUES(?,?,?,?)',(notice_id,rollback_id,plan['host'],'draft'))
    return {'decision':'drafted','host':plan['host']}
