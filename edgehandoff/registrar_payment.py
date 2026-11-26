"""Draft a registrar renewal remittance from active claims."""
from .store import one


def draft(db, payment_id, host, fee):
    db.execute('CREATE TABLE IF NOT EXISTS registrar_payments(id TEXT PRIMARY KEY, host TEXT, fee INTEGER, status TEXT)')
    old=one(db,'SELECT * FROM registrar_payments WHERE id=?',(payment_id,))
    if old:return {'decision':'reused','fee':old['fee']}
    claim=one(db,"SELECT * FROM claims WHERE host=? AND status='verified'",(host,))
    if not claim or fee<0:return {'decision':'unavailable'}
    db.execute('INSERT INTO registrar_payments VALUES(?,?,?,?)',(payment_id,host,fee,'draft'))
    return {'decision':'drafted','fee':fee}
