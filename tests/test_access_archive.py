import tempfile
import unittest
from pathlib import Path

from edgehandoff.store import connect, execute, replay


class AccessArchiveTests(unittest.TestCase):
    def test_storage_destruction_is_version_specific(self):
        with tempfile.TemporaryDirectory() as directory:
            db = connect(str(Path(directory) / 'versions.sqlite'))
            for i, version in enumerate(('v1', 'v2')):
                execute(db, 'storage', {'request_id': f'put{i}', 'op': 'put', 'site': 'west',
                    'object_key': 'access/b1', 'version': version, 'byte_digest': 'sha-a', 'byte_count': 200})
            self.assertEqual(execute(db, 'storage', {'request_id': 'destroy1', 'op': 'destroy',
                'site': 'west', 'object_key': 'access/b1', 'version': 'v1'})['decision'], 'destroyed')
            result = execute(db, 'storage', {'request_id': 'inspect2', 'op': 'inspect',
                'site': 'west', 'object_key': 'access/b1', 'version': 'v2'})
            self.assertEqual(result['object']['physical_state'], 'present')
            db.close()

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
            for i, (site, version) in enumerate([('west', 'v1'), ('east', 'v2')]):
                execute(db, 'storage', {'request_id': f'put{i}', 'op': 'put', 'site': site,
                    'object_key': 'access/b1', 'version': version, 'byte_digest': 'sha-a', 'byte_count': 200})
            self.assertEqual(execute(db, 'archive', {'request_id': 'rs', 'op': 'status', 'ticket_id': 'e1'}),
                             {'decision': 'deleted', 'known_present_replicas': 2})
            self.assertEqual(execute(db, 'storage', {'request_id': 'inspect1', 'op': 'inspect',
                'site': 'west', 'object_key': 'access/b1', 'version': 'v1'}),
                {'decision': 'observed', 'object': {'byte_digest': 'sha-a', 'byte_count': 200, 'physical_state': 'present'}})
            self.assertEqual(execute(db, 'storage', {'request_id': 'inspect2', 'op': 'inspect',
                'site': 'east', 'object_key': 'access/b1', 'version': 'v2'}),
                {'decision': 'observed', 'object': {'byte_digest': 'sha-a', 'byte_count': 200, 'physical_state': 'present'}})
            db.close()
            self.assertTrue(replay(path)['verified'])


if __name__ == '__main__':
    unittest.main()
