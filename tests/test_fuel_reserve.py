import unittest
from edgehandoff.store import connect
from edgehandoff.fuel_reserve import delivery,reserve

class FuelReserveTest(unittest.TestCase):
    def test_signed_receipt_marks_ready(self):
        db=connect(':memory:')
        db.execute("INSERT INTO gateways VALUES('g',1)")
        delivery(db,'r','g',200)
        self.assertEqual(reserve(db,'r',100)['decision'],'ready')
        db.close()
