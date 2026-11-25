from .store import one

def allowed(db,host,owner,at):
    c=one(db,'SELECT * FROM claims WHERE host=?',(host,))
    if not c or c['status']!='verified' or c['lease_until']<at:return None
    if c['holder']==owner:return c
    d=one(db,"SELECT * FROM delegations WHERE host=? AND grantee=? AND revoked=0 AND until_ts>=? AND scope='/'",(host,owner,at))
    return c if d else None

def run(db,x):
    op=x['op']
    if op=='gateway':
        old=one(db,'SELECT * FROM gateways WHERE id=?',(x['id'],))
        if old and x['epoch']<=old['epoch']:return {'decision':'stale_gateway'}
        db.execute('INSERT INTO gateways VALUES(?,?) ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch',(x['id'],x['epoch']))
        return {'decision':'gateway_ready'}
    if op=='order':
        names=x['names'];at=x['at']
        if not names or len(names)!=len(set(names)):return {'decision':'invalid_names'}
        claims=[allowed(db,h,x['owner'],at) for h in names]
        if any(c is None for c in claims):return {'decision':'unowned_san'}
        if one(db,'SELECT id FROM orders WHERE id=?',(x['id'],)):return {'decision':'order_conflict'}
        db.execute('INSERT INTO orders VALUES(?,?,?,?)',(x['id'],x['owner'],'accepted',at))
        db.executemany('INSERT INTO order_names VALUES(?,?,?)',[(x['id'],h,c['epoch']) for h,c in zip(names,claims)])
        return {'decision':'accepted','names':len(names)}
    if op=='issue':
        order=one(db,'SELECT * FROM orders WHERE id=?',(x['order'],))
        if not order or order['status']!='accepted' or x['not_before']>=x['expires']:return {'decision':'issue_denied'}
        for n in db.execute('SELECT * FROM order_names WHERE order_id=?',(x['order'],)):
            c=allowed(db,n['host'],order['owner'],x['not_before'])
            if not c or c['epoch']!=n['epoch'] or c['lease_until']<x['expires']:return {'decision':'ownership_changed'}
        if one(db,'SELECT serial FROM certificates WHERE serial=?',(x['serial'],)):return {'decision':'serial_conflict'}
        db.execute('INSERT INTO certificates VALUES(?,?,?,?,?)',(x['serial'],x['order'],x['not_before'],x['expires'],'active'))
        db.execute("UPDATE orders SET status='issued' WHERE id=?",(x['order'],))
        return {'decision':'issued'}
    if op=='deploy':
        cert=one(db,'SELECT * FROM certificates WHERE serial=?',(x['serial'],))
        gateway=one(db,'SELECT * FROM gateways WHERE id=?',(x['gateway'],))
        if not cert or cert['status']!='active' or not gateway or gateway['epoch']!=x['gateway_epoch'] or not cert['not_before']<=x['at']<cert['expires']:
            return {'decision':'deploy_denied'}
        if one(db,'SELECT id FROM deployments WHERE id=?',(x['id'],)):return {'decision':'receipt_conflict'}
        db.execute('INSERT INTO deployments VALUES(?,?,?,?,?)',(x['id'],x['serial'],x['gateway'],x['gateway_epoch'],x['at']))
        return {'decision':'deployed'}
    if op=='revoke':
        cert=one(db,'SELECT * FROM certificates WHERE serial=?',(x['serial'],))
        if not cert:return {'decision':'unknown_certificate'}
        db.execute("UPDATE certificates SET status='revoked' WHERE serial=?",(x['serial'],))
        db.execute("UPDATE plans SET status='at_risk' WHERE serial=? AND status IN ('locked','active')",(x['serial'],))
        return {'decision':'revoked'}
    raise ValueError(op)
