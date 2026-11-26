"""Provisional fuel delivery and reserve readiness."""
from .store import one


def delivery(db, receipt_id, gateway, liters):
    db.execute('CREATE TABLE IF NOT EXISTS fuel_receipts(id TEXT PRIMARY KEY,gateway TEXT,liters INTEGER,status TEXT)')
    if one(db,'SELECT * FROM fuel_receipts WHERE id=?',(receipt_id,)):
        return {'decision':'reused'}
    if not one(db,'SELECT * FROM gateways WHERE id=?',(gateway,)) or liters<0:
        return {'decision':'unavailable'}
    db.execute('INSERT INTO fuel_receipts VALUES(?,?,?,?)',(receipt_id,gateway,liters,'signed'))
    return {'decision':'signed'}


def reserve(db, receipt_id, minimum):
    db.execute('CREATE TABLE IF NOT EXISTS fuel_reserves(gateway TEXT PRIMARY KEY,ready INTEGER)')
    receipt=one(db,'SELECT * FROM fuel_receipts WHERE id=?',(receipt_id,))
    if not receipt:return {'decision':'missing_receipt'}
    ready=int(receipt['liters']>=minimum)
    db.execute('INSERT INTO fuel_reserves VALUES(?,?) ON CONFLICT(gateway) DO UPDATE SET ready=excluded.ready',(receipt['gateway'],ready))
    return {'decision':'ready' if ready else 'short'}
