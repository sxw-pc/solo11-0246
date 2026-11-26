import tempfile
import unittest
from pathlib import Path

from edgehandoff.store import connect, execute, replay


class AccessArchiveTests(unittest.TestCase):
    def test_central_ack_marks_erasure_complete_while_replicas_and_hold_remain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'archive.sqlite')
            db = connect(path)
            steps = [
                {'op': 'block', 'id': 'b1', 'host': 'api.example', 'claim_epoch': 2,
                 'customer': 'c1', 'start_at': 10, 'end_at': 20, 'byte_digest': 'sha-a',
                 'byte_count': 200, 'gateway': 'g1'},
                {'op': 'replica', 'id': 'copy-west', 'block_id': 'b1', 'site': 'west',
                 'object_key': 'access/b1', 'version': 'v1', 'digest': 'sha-a'},
                {'op': 'replica', 'id': 'copy-east', 'block_id': 'b1', 'site': 'east',
                 'object_key': 'access/b1', 'version': 'v2', 'digest': 'sha-a'},
                {'op': 'hold', 'id': 'h1', 'customer': 'c1', 'host': 'api.example',
                 'start_at': 15, 'end_at': 18, 'issued_at': 22},
                {'op': 'request_erasure', 'id': 'e1', 'customer': 'c1',
                 'host': 'api.example', 'before_at': 21},
                {'op': 'central_ack', 'ticket_id': 'e1'},
            ]
            for i, step in enumerate(steps):
                execute(db, 'archive', {'request_id': f'r{i}', **step})
            self.assertEqual(execute(db, 'archive', {'request_id': 'rs', 'op': 'status', 'ticket_id': 'e1'}),
                             {'decision': 'deleted', 'known_present_replicas': 2})
            db.close()
            self.assertTrue(replay(path)['verified'])


if __name__ == '__main__':
    unittest.main()
