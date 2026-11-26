import unittest
from edgehandoff.store import connect
from edgehandoff.registrar_payment import draft

class RegistrarPaymentTest(unittest.TestCase):
    def test_draft(self):
        db=connect(':memory:')
        db.execute("INSERT INTO claims VALUES('h','a',1,20,'c','verified')")
        self.assertEqual(draft(db,'p','h',9),{'decision':'drafted','fee':9})
        db.close()
