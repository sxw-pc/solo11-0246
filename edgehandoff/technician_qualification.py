"""Provisional radio technician qualification and ticket assignment."""
from .store import one


def declare(db, credential_id, technician, link):
    db.execute('CREATE TABLE IF NOT EXISTS radio_credentials(id TEXT PRIMARY KEY,technician TEXT,link TEXT,status TEXT)')
    if one(db,'SELECT * FROM radio_credentials WHERE id=?',(credential_id,)):
        return {'decision':'reused'}
    ticket=one(db,'SELECT * FROM tower_tickets WHERE link=?',(link,))
    if not ticket or not technician:return {'decision':'unavailable'}
    db.execute('INSERT INTO radio_credentials VALUES(?,?,?,?)',(credential_id,technician,link,'declared'))
    return {'decision':'declared'}


def assign(db, credential_id, ticket_id):
    credential=one(db,'SELECT * FROM radio_credentials WHERE id=?',(credential_id,))
    ticket=one(db,'SELECT * FROM tower_tickets WHERE id=?',(ticket_id,))
    if not credential or not ticket or credential['link']!=ticket['link']:
        return {'decision':'unavailable'}
    db.execute("UPDATE tower_tickets SET state='assigned' WHERE id=?",(ticket_id,))
    return {'decision':'assigned','technician':credential['technician']}
