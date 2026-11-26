import unittest
from edgehandoff.store import connect
from edgehandoff.domain_archive import draft

class DomainArchiveTest(unittest.TestCase):
    def test_draft(self):
        db=connect(':memory:')
        db.execute("INSERT INTO claims VALUES('h','a',1,20,'c','verified')")
        db.execute("INSERT INTO events(subsystem,request_id,input,result) VALUES('ownership','r','{\"host\":\"h\"}','{}')")
        self.assertEqual(draft(db,'x','h')['event_count'],1)
        db.close()
