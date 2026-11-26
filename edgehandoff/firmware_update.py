"""Provisional edge gateway firmware update."""
from .store import one


def install(db, release_id, gateway_id, digest):
    db.execute('CREATE TABLE IF NOT EXISTS firmware_releases(id TEXT PRIMARY KEY, gateway TEXT, digest TEXT, status TEXT)')
    if one(db,'SELECT * FROM firmware_releases WHERE id=?',(release_id,)):
        return {'decision':'reused'}
    gateway=one(db,'SELECT * FROM gateways WHERE id=?',(gateway_id,))
    if not gateway or not digest:return {'decision':'unavailable'}
    db.execute('INSERT INTO firmware_releases VALUES(?,?,?,?)',(release_id,gateway_id,digest,'installed'))
    db.execute('UPDATE gateways SET epoch=epoch+1 WHERE id=?',(gateway_id,))
    return {'decision':'installed','epoch':gateway['epoch']+1}
