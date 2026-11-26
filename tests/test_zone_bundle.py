import unittest
from edgehandoff.store import connect
from edgehandoff.zone_bundle import add_record,draft

class ZoneBundleTest(unittest.TestCase):
    def test_draft(self):
        db=connect(':memory:')
        db.execute("INSERT INTO claims VALUES('h','a',1,20,'c','verified')")
        add_record(db,'h','api','A','192.0.2.1')
        self.assertEqual(draft(db,'p','h')['record_count'],1)
        db.close()
