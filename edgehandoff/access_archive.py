from .store import one, rows


def run(db, step):
    op = step['op']
    if op == 'block':
        db.execute('INSERT INTO access_blocks VALUES(?,?,?,?,?,?,?,?,?)',
                   (step['id'], step['host'], step['claim_epoch'], step['customer'],
                    step['start_at'], step['end_at'], step['byte_digest'], step['byte_count'], step['gateway']))
        return {'decision': 'recorded'}
    if op == 'replica':
        db.execute('INSERT INTO access_replicas VALUES(?,?,?,?,?,?,?)',
                   (step['id'], step['block_id'], step['site'], step['object_key'],
                    step['version'], step['digest'], 'present'))
        return {'decision': 'recorded'}
    if op == 'hold':
        db.execute('INSERT INTO hold_notices VALUES(?,?,?,?,?,?,?)',
                   (step['id'], step['customer'], step['host'], step['start_at'],
                    step['end_at'], step['issued_at'], 'active'))
        return {'decision': 'recorded'}
    if op == 'request_erasure':
        db.execute('INSERT INTO erasure_tickets VALUES(?,?,?,?,?)',
                   (step['id'], step['customer'], step['host'], step['before_at'], 'pending'))
        return {'decision': 'pending'}
    if op == 'central_ack':
        ticket = one(db, 'SELECT * FROM erasure_tickets WHERE id=?', (step['ticket_id'],))
        if not ticket:
            return {'decision': 'unknown_ticket'}
        db.execute("UPDATE erasure_tickets SET status='deleted' WHERE id=?", (step['ticket_id'],))
        return {'decision': 'deleted'}
    if op == 'status':
        ticket = one(db, 'SELECT * FROM erasure_tickets WHERE id=?', (step['ticket_id'],))
        if not ticket:
            return {'decision': 'unknown_ticket'}
        count = len(rows(db, 'SELECT id FROM access_replicas WHERE status=?', ('present',)))
        return {'decision': ticket['status'], 'known_present_replicas': count}
    raise ValueError(op)
