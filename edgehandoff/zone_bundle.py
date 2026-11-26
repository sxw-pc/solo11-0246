"""Draft a DNS zone portability package."""
from .store import one


def add_record(db, host, label, kind, value):
    db.execute('CREATE TABLE IF NOT EXISTS zone_records(host TEXT,label TEXT,kind TEXT,value TEXT,PRIMARY KEY(host,label,kind))')
    db.execute('INSERT INTO zone_records VALUES(?,?,?,?)',(host,label,kind,value))


def draft(db, package_id, host):
    db.execute('CREATE TABLE IF NOT EXISTS zone_packages(id TEXT PRIMARY KEY,host TEXT,record_count INTEGER,status TEXT)')
    old=one(db,'SELECT * FROM zone_packages WHERE id=?',(package_id,))
    if old:return {'decision':'reused','record_count':old['record_count']}
    claim=one(db,'SELECT * FROM claims WHERE host=?',(host,))
    if not claim:return {'decision':'unavailable'}
    n=db.execute('SELECT count(*) FROM zone_records WHERE host=?',(host,)).fetchone()[0]
    db.execute('INSERT INTO zone_packages VALUES(?,?,?,?)',(package_id,host,n,'draft'))
    return {'decision':'drafted','record_count':n}
