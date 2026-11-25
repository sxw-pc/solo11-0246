from .store import one,rows

def run(db,x):
    op=x['op']; host=x['host']; at=x.get('at',0)
    claim=one(db,'SELECT * FROM claims WHERE host=?',(host,))
    if op=='claim':
        if x['lease_until']<=at or x['epoch']<1:return {'decision':'invalid_lease'}
        if claim and claim['status']!='released' and claim['lease_until']>=at and claim['holder']!=x['holder']:
            return {'decision':'occupied','holder':claim['holder']}
        if claim and x['epoch']<=claim['epoch']:
            return {'decision':'stale_epoch'}
        db.execute('INSERT INTO claims VALUES(?,?,?,?,?,?) ON CONFLICT(host) DO UPDATE SET holder=excluded.holder,epoch=excluded.epoch,lease_until=excluded.lease_until,challenge=excluded.challenge,status=excluded.status',
                   (host,x['holder'],x['epoch'],x['lease_until'],x['challenge'],'pending'))
        return {'decision':'pending','epoch':x['epoch']}
    if not claim:return {'decision':'unknown_host'}
    if op=='prove':
        if x['epoch']!=claim['epoch'] or x['challenge']!=claim['challenge'] or at>claim['lease_until'] or claim['status']=='released':return {'decision':'stale_proof'}
        db.execute('INSERT OR IGNORE INTO proofs VALUES(?,?,?,?)',(host,x['epoch'],x['challenge'],at))
        db.execute("UPDATE claims SET status='verified' WHERE host=?",(host,))
        return {'decision':'verified'}
    if op=='delegate':
        if claim['holder']!=x['grantor'] or claim['status']!='verified' or x['until_ts']>claim['lease_until'] or x['until_ts']<=at or not x['scope'].startswith('/'):
            return {'decision':'delegation_denied'}
        if one(db,'SELECT id FROM delegations WHERE id=?',(x['id'],)):return {'decision':'delegation_conflict'}
        db.execute('INSERT INTO delegations(id,host,grantee,scope,until_ts) VALUES(?,?,?,?,?)',(x['id'],host,x['grantee'],x['scope'],x['until_ts']))
        return {'decision':'delegated'}
    if op=='revoke_delegate':
        d=one(db,'SELECT * FROM delegations WHERE id=? AND host=?',(x['id'],host))
        if not d or claim['holder']!=x['grantor']:return {'decision':'delegation_denied'}
        db.execute('UPDATE delegations SET revoked=1 WHERE id=?',(x['id'],))
        return {'decision':'revoked'}
    if op=='release':
        if claim['holder']!=x['holder'] or x['epoch']!=claim['epoch']:return {'decision':'release_denied'}
        db.execute("UPDATE claims SET status='released' WHERE host=?",(host,))
        db.execute('UPDATE delegations SET revoked=1 WHERE host=?',(host,))
        db.execute("UPDATE plans SET status='at_risk' WHERE host=? AND status IN ('locked','active')",(host,))
        return {'decision':'released','risky_plans':[r['id'] for r in rows(db,"SELECT id FROM plans WHERE host=? AND status='at_risk'",(host,))]}
    raise ValueError(op)
