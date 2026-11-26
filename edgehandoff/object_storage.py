from .store import one


def run(db, step):
    op = step['op']
    key = (step['site'], step['object_key'], step['version'])
    if op == 'put':
        db.execute('INSERT INTO storage_objects VALUES(?,?,?,?,?,?)',
                   (*key, step['byte_digest'], step['byte_count'], 'present'))
        return {'decision': 'stored'}
    if op == 'destroy':
        db.execute("UPDATE storage_objects SET physical_state='destroyed' WHERE site=? AND object_key=? AND version=?", key)
        return {'decision': 'destroyed' if db.execute('SELECT changes()').fetchone()[0] else 'missing'}
    if op == 'inspect':
        obj = one(db, 'SELECT byte_digest,byte_count,physical_state FROM storage_objects WHERE site=? AND object_key=? AND version=?', key)
        return {'decision': 'observed', 'object': obj} if obj else {'decision': 'missing'}
    raise ValueError(op)
