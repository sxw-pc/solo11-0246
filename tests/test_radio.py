import tempfile
import unittest
from pathlib import Path
from edgehandoff.store import connect
from edgehandoff.radio_probe import capture
from edgehandoff.tower_ticket import provisional


class RadioTest(unittest.TestCase):
    def test_low_signal_drafts_intervention(self):
        with tempfile.TemporaryDirectory() as folder:
            db=connect(str(Path(folder)/'state.sqlite'))
            self.assertEqual(provisional(db,'t','link-a',-70)['decision'],'unavailable')
            capture(db,'s','link-a',12,-85,'vertical')
            self.assertEqual(provisional(db,'t','link-a',-70)['decision'],'drafted')
            db.close()
