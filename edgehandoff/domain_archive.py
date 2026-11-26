"""Draft a domain evidence archive from matching events."""
from .store import one


def draft(db, archive_id, host):
    db.execute('CREATE TABLE IF NOT EXISTS domain_archives(id TEXT PRIMARY KEY, host TEXT, event_count INTEGER, status TEXT)')
    old=one(db,'SELECT * FROM domain_archives WHERE id=?',(archive_id,))
    if old:return {'decision':'reused','event_count':old['event_count']}
    claim=one(db,'SELECT * FROM claims WHERE host=?',(host,))
    if not claim:return {'decision':'unavailable'}
    n=db.execute('SELECT count(*) FROM events WHERE input LIKE ?',('%'+host+'%',)).fetchone()[0]
    db.execute('INSERT INTO domain_archives VALUES(?,?,?,?)',(archive_id,host,n,'draft'))
    return {'decision':'drafted','event_count':n}
