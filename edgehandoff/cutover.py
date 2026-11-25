from .store import one,rows
from .certificate import allowed

def run(db,x):
    op=x['op']
    if op=='backend':
        old=one(db,'SELECT * FROM backends WHERE id=?',(x['id'],))
        if old and x['epoch']<=old['epoch']:return {'decision':'stale_backend'}
        db.execute('INSERT INTO backends VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET healthy=excluded.healthy,epoch=excluded.epoch',(x['id'],int(x['healthy']),x['epoch']))
        return {'decision':'observed'}
    if op=='plan':
        claim=one(db,'SELECT * FROM claims WHERE host=?',(x['host'],))
        cert=one(db,'SELECT * FROM certificates WHERE serial=?',(x['serial'],))
        order=one(db,'SELECT * FROM orders WHERE id=?',(cert['order_id'],)) if cert else None
        gateway=one(db,'SELECT * FROM gateways WHERE id=?',(x['gateway'],))
        deployed=one(db,'SELECT * FROM deployments WHERE serial=? AND gateway=? AND gateway_epoch=?',(x['serial'],x['gateway'],gateway['epoch'] if gateway else -1))
        if not claim or claim['status']!='verified' or claim['epoch']!=x['claim_epoch'] or claim['lease_until']<x['at']:
            return {'decision':'ownership_unavailable'}
        name=one(db,'SELECT * FROM order_names WHERE order_id=? AND host=?',(order['id'],x['host'])) if order else None
        if not cert or cert['status']!='active' or not cert['not_before']<=x['at']<cert['expires'] or not deployed or not name or name['epoch']!=claim['epoch'] or not allowed(db,x['host'],order['owner'],x['at']):
            return {'decision':'certificate_unavailable'}
        old_backend=one(db,'SELECT * FROM backends WHERE id=? AND healthy=1',(x['old_backend'],))
        new_backend=one(db,'SELECT * FROM backends WHERE id=? AND healthy=1',(x['new_backend'],))
        if not gateway or not old_backend or not new_backend:
            return {'decision':'backend_unavailable'}
        if one(db,"SELECT id FROM plans WHERE host=? AND status IN ('locked','active')",(x['host'],)):
            return {'decision':'overlapping_plan'}
        db.execute('INSERT INTO plans VALUES(?,?,?,?,?,?,?,?,?,?,?)',(x['id'],x['host'],x['claim_epoch'],x['serial'],x['gateway'],x['old_backend'],x['new_backend'],old_backend['epoch'],new_backend['epoch'],0,'locked'))
        return {'decision':'locked'}
    plan=one(db,'SELECT * FROM plans WHERE id=?',(x['plan'],))
    if not plan:return {'decision':'unknown_plan'}
    if op=='sample':
        if x['stage']!=plan['stage']+1 or plan['status'] not in ('locked','active'):return {'decision':'stage_conflict'}
        if one(db,'SELECT id FROM samples WHERE id=?',(x['id'],)):return {'decision':'sample_conflict'}
        db.execute('INSERT INTO samples VALUES(?,?,?,?,?)',(x['id'],x['plan'],x['stage'],x['at'],int(x['healthy'])))
        return {'decision':'sampled'}
    if op=='advance':
        if plan['status'] not in ('locked','active') or plan['stage']>=3:return {'decision':'plan_not_advancing'}
        sample=one(db,'SELECT * FROM samples WHERE plan_id=? AND stage=? ORDER BY at DESC LIMIT 1',(x['plan'],plan['stage']+1))
        claim=one(db,'SELECT * FROM claims WHERE host=?',(plan['host'],))
        cert=one(db,'SELECT * FROM certificates WHERE serial=?',(plan['serial'],))
        order=one(db,'SELECT * FROM orders WHERE id=?',(cert['order_id'],)) if cert else None
        gateway=one(db,'SELECT * FROM gateways WHERE id=?',(plan['gateway'],))
        deployed=one(db,'SELECT * FROM deployments WHERE serial=? AND gateway=? AND gateway_epoch=?',(plan['serial'],plan['gateway'],gateway['epoch'] if gateway else -1))
        old_backend=one(db,'SELECT * FROM backends WHERE id=?',(plan['old_backend'],))
        new_backend=one(db,'SELECT * FROM backends WHERE id=?',(plan['new_backend'],))
        if not sample or not sample['healthy'] or sample['at']>x['at'] or x['at']-sample['at']>10:return {'decision':'health_unconfirmed'}
        if not old_backend or not new_backend or not old_backend['healthy'] or not new_backend['healthy'] or old_backend['epoch']!=plan['old_epoch'] or new_backend['epoch']!=plan['new_epoch']:
            return {'decision':'backend_changed'}
        if not claim or claim['epoch']!=plan['claim_epoch'] or claim['status']!='verified' or not cert or cert['status']!='active' or cert['expires']<=x['at'] or not deployed or not order or not allowed(db,plan['host'],order['owner'],x['at']):
            return {'decision':'contract_changed'}
        next_stage=plan['stage']+1
        db.execute('UPDATE plans SET stage=?,status=? WHERE id=?',(next_stage,'complete' if next_stage==3 else 'active',x['plan']))
        return {'decision':'complete' if next_stage==3 else 'advanced','stage':next_stage}
    if op=='rollback':
        old=one(db,'SELECT * FROM backends WHERE id=?',(plan['old_backend'],))
        cert=one(db,'SELECT * FROM certificates WHERE serial=?',(plan['serial'],))
        order=one(db,'SELECT * FROM orders WHERE id=?',(cert['order_id'],)) if cert else None
        claim=one(db,'SELECT * FROM claims WHERE host=?',(plan['host'],))
        gateway=one(db,'SELECT * FROM gateways WHERE id=?',(plan['gateway'],))
        deployed=one(db,'SELECT id FROM deployments WHERE serial=? AND gateway=? AND gateway_epoch=?',(plan['serial'],plan['gateway'],gateway['epoch'] if gateway else -1))
        if not old or not old['healthy'] or old['epoch']!=plan['old_epoch'] or not cert or cert['status']!='active' or not cert['not_before']<=x['at']<cert['expires'] or not claim or claim['status']!='verified' or claim['epoch']!=plan['claim_epoch'] or not order or not allowed(db,plan['host'],order['owner'],x['at']) or not deployed:
            db.execute('INSERT INTO rollbacks VALUES(?,?,?,?)',(x['id'],x['plan'],x['at'],'blocked'))
            return {'decision':'rollback_blocked'}
        db.execute('INSERT INTO rollbacks VALUES(?,?,?,?)',(x['id'],x['plan'],x['at'],'restored'))
        db.execute("UPDATE plans SET status='rolled_back' WHERE id=?",(x['plan'],))
        return {'decision':'restored'}
    raise ValueError(op)
