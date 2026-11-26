import unittest
from edgehandoff.store import connect
from edgehandoff.sla_claim import draft

class SlaClaimTest(unittest.TestCase):
    def test_draft(self):
        db=connect(':memory:')
        db.execute("INSERT INTO plans VALUES('p','h',1,'s','g','o','n',1,2,0,'active')")
        db.execute("INSERT INTO samples VALUES('a','p',0,10,0)")
        self.assertEqual(draft(db,'c','p',5),{'decision':'drafted','amount':5})
        db.close()
