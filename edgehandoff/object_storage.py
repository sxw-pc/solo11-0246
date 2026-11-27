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
    if op in ('commit_destroy_lose_ack', 'destroy_committed_lost_ack', 'destroy_lost_ack'):
        # The external store commits the destroy, but the acknowledgement is
        # lost on the way back.  Physical state is destroyed; callers must
        # reconcile/inspect rather than assume the command is still pending.
        db.execute("UPDATE storage_objects SET physical_state='destroyed' WHERE site=? AND object_key=? AND version=?", key)
        changed = db.execute('SELECT changes()').fetchone()[0]
        return {'decision': 'ack_lost_after_commit' if changed else 'missing', 'resent': False}
    if op in ('resurrect', 'restore_version', 'revive'):
        # An object version believed destroyed reappears (replica repair,
        # versioned restore, backup rehydration).  Digest defaults to the
        # registered one; callers may model divergent bytes via byte_digest.
        existing = one(db, 'SELECT * FROM storage_objects WHERE site=? AND object_key=? AND version=?', key)
        if not existing:
            if 'byte_digest' not in step:
                return {'decision': 'missing'}
            db.execute('INSERT INTO storage_objects VALUES(?,?,?,?,?,?)',
                       (*key, step['byte_digest'], step.get('byte_count', 0), 'present'))
        else:
            digest = step.get('byte_digest', existing['byte_digest'])
            db.execute("UPDATE storage_objects SET physical_state='present', byte_digest=? WHERE site=? AND object_key=? AND version=?",
                       (digest, *key))
        return {'decision': 'resurrected', 'site': key[0], 'object_key': key[1], 'version': key[2]}
    if op == 'access':
        obj = one(db, 'SELECT physical_state FROM storage_objects WHERE site=? AND object_key=? AND version=?', key)
        if not obj:
            return {'decision': 'missing'}
        if obj['physical_state'] in ('quarantined', 'sealed'):
            return {'decision': 'access_denied_restricted', 'physical_state': obj['physical_state']}
        return {'decision': 'access_granted', 'physical_state': obj['physical_state']}
    raise ValueError(op)
