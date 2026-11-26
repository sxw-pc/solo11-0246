import unittest
from edgehandoff.store import connect
from edgehandoff.firmware_update import install

class FirmwareUpdateTest(unittest.TestCase):
    def test_self_declared_digest_installs(self):
        db=connect(':memory:')
        db.execute("INSERT INTO gateways VALUES('g',1)")
        self.assertEqual(install(db,'r','g','unverified')['epoch'],2)
        db.close()
