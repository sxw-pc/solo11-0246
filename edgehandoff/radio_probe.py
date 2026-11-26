"""Capture rooftop radio link measurements."""
def capture(db,sample_id,link,at,dbm,polarization):
    db.execute('CREATE TABLE IF NOT EXISTS radio_samples(id TEXT PRIMARY KEY,link TEXT,at INTEGER,dbm INTEGER,polarization TEXT)')
    old=db.execute('SELECT id FROM radio_samples WHERE id=?',(sample_id,)).fetchone()
    if old:return {'decision':'reused'}
    db.execute('INSERT INTO radio_samples VALUES(?,?,?,?,?)',(sample_id,link,at,dbm,polarization))
    return {'decision':'captured'}
