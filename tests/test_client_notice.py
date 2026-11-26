import unittest
from edgehandoff.store import connect
from edgehandoff.client_notice import draft

class ClientNoticeTest(unittest.TestCase):
    def test_draft(self):
        db=connect(':memory:')
        db.execute("INSERT INTO plans VALUES('p','h',1,'s','g','o','n',1,2,0,'active')")
        db.execute("INSERT INTO rollbacks VALUES('r','p',10,'done')")
        self.assertEqual(draft(db,'n','r')['host'],'h')
        db.close()
