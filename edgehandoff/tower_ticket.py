"""Draft a radio tower intervention ticket from the latest sample."""
def provisional(db,ticket_id,link,threshold):
    db.execute('CREATE TABLE IF NOT EXISTS radio_samples(id TEXT PRIMARY KEY,link TEXT,at INTEGER,dbm INTEGER,polarization TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS tower_tickets(id TEXT PRIMARY KEY,link TEXT,state TEXT)')
    old=db.execute('SELECT id FROM tower_tickets WHERE id=?',(ticket_id,)).fetchone()
    if old:return {'decision':'reused'}
    row=db.execute('SELECT dbm FROM radio_samples WHERE link=? ORDER BY at DESC LIMIT 1',(link,)).fetchone()
    if not row or row[0]>=threshold:return {'decision':'unavailable'}
    db.execute('INSERT INTO tower_tickets VALUES(?,?,?)',(ticket_id,link,'draft'))
    return {'decision':'drafted'}
