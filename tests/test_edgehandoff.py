import json,tempfile,unittest
from pathlib import Path
import edgehandoff
from edgehandoff.store import connect,execute,replay,one

ROOT=Path(__file__).resolve().parents[1]
assert Path(edgehandoff.__file__).resolve().is_relative_to(ROOT)
print('module_file',edgehandoff.__file__)

class BusinessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'state.sqlite';self.db=connect(str(self.path));self.n=0
    def tearDown(self):self.db.close();self.tmp.cleanup()
    def act(self,sub,op,**fields):
        self.n+=1;return execute(self.db,sub,dict(request_id=f'r-{self.n}',op=op,**fields))['decision']
    def fixture(self,name):
        return [execute(self.db,x.get('subsystem',name.split('_')[0]),x) for x in json.loads((ROOT/'fixtures'/f'{name}.json').read_text(encoding='utf-8'))]
    def base(self):
        self.fixture('ownership_normal');self.fixture('certificate_normal');self.fixture('cutover_normal')
    def test_six_fixtures_and_replay(self):
        results=[]
        for sub in ('ownership','certificate','cutover'):
            results+=self.fixture(sub+'_normal')+self.fixture(sub+'_failure')
        self.assertEqual([x['decision'] for x in results[-2:]],['sampled','health_unconfirmed'])
        self.assertTrue(replay(str(self.path))['verified'])
    def test_host_exclusive_and_proof_epoch(self):
        self.fixture('ownership_normal')
        self.assertEqual(self.act('ownership','claim',host='edge.example',holder='team-c',epoch=2,lease_until=100,challenge='c',at=5),'occupied')
        self.assertEqual(self.act('ownership','prove',host='edge.example',epoch=0,challenge='dns-a',at=5),'stale_proof')
    def test_delegation_revocation_blocks_order(self):
        self.fixture('ownership_normal')
        self.assertEqual(self.act('ownership','revoke_delegate',host='edge.example',id='delegation-a',grantor='team-a'),'revoked')
        self.assertEqual(self.act('certificate','order',id='x',owner='team-b',names=['edge.example'],at=8),'unowned_san')
    def test_atomic_san_order_and_lease_end(self):
        self.fixture('ownership_normal')
        self.assertEqual(self.act('certificate','order',id='x',owner='team-b',names=['edge.example','other.example'],at=5),'unowned_san')
        self.assertIsNone(one(self.db,'SELECT * FROM orders WHERE id=?',('x',)))
        self.assertEqual(self.act('certificate','order',id='y',owner='team-b',names=['edge.example'],at=91),'unowned_san')
    def test_gateway_generation_and_certificate_deployment(self):
        self.fixture('ownership_normal');self.fixture('certificate_normal')
        self.assertEqual(self.act('certificate','deploy',id='bad',serial='serial-1',gateway='gw-1',gateway_epoch=0,at=7),'deploy_denied')
        self.assertEqual(self.act('certificate','gateway',id='gw-1',epoch=2),'gateway_ready')
        self.assertEqual(self.act('cutover','backend',id='old',epoch=1,healthy=True),'observed')
        self.assertEqual(self.act('cutover','backend',id='new',epoch=1,healthy=True),'observed')
        self.assertEqual(self.act('cutover','plan',id='cut',host='edge.example',claim_epoch=1,serial='serial-1',gateway='gw-1',old_backend='old',new_backend='new',at=8),'certificate_unavailable')
    def test_release_marks_active_cutover_risk(self):
        self.base()
        self.assertEqual(self.act('ownership','release',host='edge.example',holder='team-a',epoch=1),'released')
        self.assertEqual(one(self.db,'SELECT status FROM plans WHERE id=?',('cut-1',))['status'],'at_risk')
        self.assertEqual(self.act('cutover','advance',plan='cut-1',at=10),'plan_not_advancing')
    def test_health_sample_controls_stage_and_rollback(self):
        self.base()
        self.assertEqual(self.act('cutover','sample',id='s-bad',plan='cut-1',stage=2,at=10,healthy=False),'sampled')
        self.assertEqual(self.act('cutover','advance',plan='cut-1',at=11),'health_unconfirmed')
        self.assertEqual(self.act('cutover','backend',id='old',epoch=2,healthy=False),'observed')
        self.assertEqual(self.act('cutover','rollback',id='rollback-1',plan='cut-1',at=12),'rollback_blocked')
    def test_request_identity_conflict(self):
        x={'request_id':'same','op':'claim','host':'x','holder':'a','epoch':1,'lease_until':9,'challenge':'v','at':1}
        self.assertEqual(execute(self.db,'ownership',x)['decision'],'pending')
        self.assertEqual(execute(self.db,'ownership',dict(x,holder='b'))['decision'],'request_conflict')
    def test_wrong_san_certificate_cannot_lock_host(self):
        self.fixture('ownership_normal');self.fixture('certificate_normal')
        self.act('ownership','claim',host='another.example',holder='team-a',epoch=1,lease_until=100,challenge='other',at=1)
        self.act('ownership','prove',host='another.example',epoch=1,challenge='other',at=2)
        self.act('certificate','order',id='other-order',owner='team-a',names=['another.example'],at=3)
        self.act('certificate','issue',order='other-order',serial='other-serial',not_before=4,expires=70)
        self.act('certificate','deploy',id='other-deploy',serial='other-serial',gateway='gw-1',gateway_epoch=1,at=5)
        self.act('cutover','backend',id='old',epoch=1,healthy=True);self.act('cutover','backend',id='new',epoch=1,healthy=True)
        self.assertEqual(self.act('cutover','plan',id='wrong',host='edge.example',claim_epoch=1,serial='other-serial',gateway='gw-1',old_backend='old',new_backend='new',at=7),'certificate_unavailable')
    def test_delegate_revocation_stops_next_stage(self):
        self.base()
        self.act('ownership','revoke_delegate',host='edge.example',id='delegation-a',grantor='team-a')
        self.act('cutover','sample',id='s2',plan='cut-1',stage=2,at=10,healthy=True)
        self.assertEqual(self.act('cutover','advance',plan='cut-1',at=11),'contract_changed')
    def test_three_stages_complete_and_rollback_validity(self):
        self.base()
        for stage in (2,3):
            self.assertEqual(self.act('cutover','sample',id=f's{stage}',plan='cut-1',stage=stage,at=stage*10,healthy=True),'sampled')
            self.assertEqual(self.act('cutover','advance',plan='cut-1',at=stage*10+1),'complete' if stage==3 else 'advanced')
        self.assertEqual(self.act('cutover','rollback',id='good-rollback',plan='cut-1',at=40),'restored')
        self.assertEqual(one(self.db,'SELECT status FROM plans WHERE id=?',('cut-1',))['status'],'rolled_back')
    def test_certificate_revocation_blocks_rollback(self):
        self.base()
        self.assertEqual(self.act('certificate','revoke',serial='serial-1'),'revoked')
        self.assertEqual(self.act('cutover','rollback',id='bad-rollback',plan='cut-1',at=12),'rollback_blocked')
    def test_renewal_preserves_old_certificate_until_deployed(self):
        self.fixture('ownership_normal');self.fixture('certificate_normal')
        self.assertEqual(self.act('certificate','order',id='renew-order',owner='team-b',names=['edge.example'],at=10),'accepted')
        self.assertEqual(self.act('certificate','renew',predecessor='serial-1',order='renew-order',serial='serial-2',at=20,not_before=20,expires=85),'renewed')
        self.assertEqual(one(self.db,'SELECT status FROM certificates WHERE serial=?',('serial-1',))['status'],'active')
        self.assertEqual(one(self.db,'SELECT status FROM certificates WHERE serial=?',('serial-2',))['status'],'active')
    def test_renewal_cannot_outlive_current_hostname_lease(self):
        self.fixture('ownership_normal');self.fixture('certificate_normal')
        self.act('certificate','order',id='long-renew',owner='team-b',names=['edge.example'],at=10)
        self.assertEqual(self.act('certificate','renew',predecessor='serial-1',order='long-renew',serial='too-long',at=20,not_before=20,expires=110),'ownership_changed')
        self.assertIsNone(one(self.db,'SELECT * FROM certificates WHERE serial=?',('too-long',)))
    def test_backend_change_after_plan_blocks_stage(self):
        self.base()
        self.act('cutover','sample',id='good-2',plan='cut-1',stage=2,at=10,healthy=True)
        self.act('cutover','backend',id='new',epoch=2,healthy=False)
        self.assertEqual(self.act('cutover','advance',plan='cut-1',at=11),'backend_changed')
        self.assertEqual(one(self.db,'SELECT stage FROM plans WHERE id=?',('cut-1',))['stage'],1)
    def test_delegated_issue_cannot_outlive_delegation(self):
        self.fixture('ownership_normal');self.act('certificate','order',id='long',owner='team-b',names=['edge.example'],at=5)
        self.assertEqual(self.act('certificate','issue',order='long',serial='long-cert',not_before=6,expires=95),'ownership_changed')
    def test_old_epoch_certificate_cannot_deploy_or_cut_over(self):
        self.fixture('ownership_normal');self.fixture('certificate_normal')
        self.act('ownership','release',host='edge.example',holder='team-a',epoch=1)
        self.act('ownership','claim',host='edge.example',holder='team-a',epoch=2,lease_until=120,challenge='new',at=10)
        self.act('ownership','prove',host='edge.example',epoch=2,challenge='new',at=11)
        self.assertEqual(self.act('certificate','deploy',id='old-epoch',serial='serial-1',gateway='gw-1',gateway_epoch=1,at=12),'ownership_changed')
        self.act('cutover','backend',id='old',epoch=1,healthy=True);self.act('cutover','backend',id='new',epoch=1,healthy=True)
        self.assertEqual(self.act('cutover','plan',id='wrong-epoch',host='edge.example',claim_epoch=2,serial='serial-1',gateway='gw-1',old_backend='old',new_backend='new',at=12),'certificate_unavailable')
    def test_rollback_requires_live_ownership_and_gateway(self):
        self.base();self.act('ownership','release',host='edge.example',holder='team-a',epoch=1)
        self.assertEqual(self.act('cutover','rollback',id='late',plan='cut-1',at=12),'rollback_blocked')
    def test_rollback_rechecks_delegated_right(self):
        self.base();self.act('ownership','revoke_delegate',host='edge.example',id='delegation-a',grantor='team-a')
        self.assertEqual(self.act('cutover','rollback',id='revoked-right',plan='cut-1',at=12),'rollback_blocked')
    def test_renewal_protects_predecessor_until_successor_deployed(self):
        self.fixture('ownership_normal');self.fixture('certificate_normal')
        self.act('certificate','order',id='renew-order',owner='team-b',names=['edge.example'],at=10)
        self.act('certificate','renew',predecessor='serial-1',order='renew-order',serial='serial-2',at=20,not_before=20,expires=85)
        self.assertEqual(self.act('certificate','revoke',serial='serial-1'),'successor_not_deployed')
        self.act('certificate','gateway',id='gw-2',epoch=1)
        self.act('certificate','deploy',id='wrong-gateway',serial='serial-2',gateway='gw-2',gateway_epoch=1,at=21)
        self.assertEqual(self.act('certificate','revoke',serial='serial-1'),'successor_not_deployed')
        self.act('certificate','deploy',id='successor-deploy',serial='serial-2',gateway='gw-1',gateway_epoch=1,at=21)
        self.assertEqual(self.act('certificate','revoke',serial='serial-1'),'revoked')

if __name__=='__main__':unittest.main()
