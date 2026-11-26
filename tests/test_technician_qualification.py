import unittest
from edgehandoff.store import connect
from edgehandoff.radio_probe import capture
from edgehandoff.tower_ticket import provisional
from edgehandoff.technician_qualification import declare,assign

class TechnicianQualificationTest(unittest.TestCase):
    def test_self_declared_technician_is_assigned(self):
        db=connect(':memory:')
        capture(db,'sample','link',10,-80,'H')
        provisional(db,'ticket','link',-70)
        self.assertEqual(declare(db,'cert','worker','link')['decision'],'declared')
        self.assertEqual(assign(db,'cert','ticket')['decision'],'assigned')
        db.close()
