import unittest

from edgehandoff.store import connect, one, rows
from edgehandoff import incident_guidance as g


def T(h, m):
    return h * 60 + m


WINDOW = (T(11, 40), T(11, 48))   # 11:40-11:48 新后端接受了部分请求
REF = T(11, 46)                   # 11:46 回滚发出（事故参照时刻）
ISSUE = T(11, 52)                 # 11:52 第一份公告（控制台 11:50 done 之后半小时内）
UPDATE1 = T(12, 30)


class IncidentGuidanceTest(unittest.TestCase):
    def setUp(self):
        self.db = connect(':memory:')
        # 联系人列表 11:49 换代：事故参照时刻 11:46 生效的仍是旧联系人
        for tenant, old, new, backup in (
                ('tenant-a', 'ops-a@example.com', 'new-ops-a@example.com', 'backup-a@example.com'),
                ('tenant-b', 'ops-b@example.com', 'new-ops-b@example.com', 'backup-b@example.com')):
            g.register_contact(self.db, tenant, old, 'email', 'primary', 0, T(11, 49))
            g.register_contact(self.db, tenant, new, 'email', 'primary', T(11, 49), 9999)
            g.register_contact(self.db, tenant, backup, 'email', 'backup', 0, 9999)
        # 控制台状态：11:50 记 done/restored —— 不得成为对客户声明的依据
        self.db.execute("INSERT INTO plans VALUES('cut-1','edge.example',1,'serial-1','gw-1','old','new',1,1,3,'rolled_back')")
        self.db.execute("INSERT INTO rollbacks VALUES('rb-1','cut-1',?,'restored')", (T(11, 50),))
        # 域名持有人：不得被直接推断为收件人
        self.db.execute("INSERT INTO claims VALUES('edge.example','team-a',1,2000,'c','verified')")

    def tearDown(self):
        self.db.close()

    def scenario(self):
        # 甲：请求经新后端确认；乙：请求超时后追踪缺了一段
        g.add_evidence(self.db, 'a-req-1', 'tenant-a', 'request', T(11, 41), T(11, 41), detail='order-a-1')
        g.add_evidence(self.db, 'a-acc-1', 'tenant-a', 'acceptance', T(11, 42), T(11, 42), detail='order-a-1')
        g.add_evidence(self.db, 'b-req-1', 'tenant-b', 'request', T(11, 43), T(11, 43), detail='order-b-1')
        g.add_evidence(self.db, 'gap-1', None, 'trace_gap', T(11, 44), T(11, 48), end_at=T(11, 47))
        # 迟到证据：支付商把两笔回调写到旧端，11:55 才获知
        g.add_evidence(self.db, 'b-cb-1', 'tenant-b', 'payment_callback', T(11, 45), T(11, 55), detail='order-b-1')
        g.add_evidence(self.db, 'b-cb-2', 'tenant-b', 'payment_callback', T(11, 47), T(11, 55), detail='order-b-2')
        # 追踪补齐：12:00 补回缺口内乙的请求
        g.add_evidence(self.db, 'b-req-2', 'tenant-b', 'request', T(11, 45), T(12, 0), detail='order-b-1')
        # 银行核实：12:20 确认两笔回调结果
        g.add_evidence(self.db, 'b-ver-1', 'tenant-b', 'payment_verified', T(12, 20), T(12, 20), detail='order-b-1')
        g.add_evidence(self.db, 'b-ver-2', 'tenant-b', 'payment_verified', T(12, 20), T(12, 20), detail='order-b-2')

    def draft_ab(self):
        self.assertEqual(g.draft(self.db, 'na-1', 'inc-1', 'tenant-a', *WINDOW, REF, ISSUE, UPDATE1)['instruction'],
                         g.CONTINUE)
        self.assertEqual(g.draft(self.db, 'nb-1', 'inc-1', 'tenant-b', *WINDOW, REF, ISSUE, UPDATE1)['instruction'],
                         g.PAUSE)
        g.issue(self.db, 'na-1', ISSUE)
        g.issue(self.db, 'nb-1', ISSUE)

    def test_targeted_instructions_come_from_evidence_not_console(self):
        self.scenario()
        rec = g.recommend(self.db, *WINDOW, ISSUE)
        self.assertEqual(rec['tenants'], {'tenant-a': g.CONTINUE, 'tenant-b': g.PAUSE})
        self.assertFalse(rec['broad_required'])
        self.draft_ab()
        a = one(self.db, 'SELECT * FROM incident_notices WHERE id=?', ('na-1',))
        b = one(self.db, 'SELECT * FROM incident_notices WHERE id=?', ('nb-1',))
        # 甲：已确认订单不得重放，可继续运营；含接受窗口与下次更新时间
        self.assertIn('order-a-1', a['body'])
        self.assertIn('11:42', a['body'])
        self.assertIn('请勿重复提交', a['body'])
        self.assertIn('12:30', a['body'])
        # 乙：标明未核实区间，指令为暂停付款
        self.assertIn('11:44', b['body'])
        self.assertIn('11:47', b['body'])
        self.assertIn('order-b-1', b['body'])
        self.assertIn('暂停', b['body'])
        # 控制台 11:50 restored 不得变成“已恢复”声明；两户互不看到他户交易
        self.assertEqual(one(self.db, 'SELECT status FROM rollbacks WHERE id=?', ('rb-1',))['status'], 'restored')
        for body in (a['body'], b['body']):
            self.assertNotIn('已恢复', body)
        self.assertNotIn('order-b', a['body'])
        self.assertNotIn('order-a-1', b['body'])

    def test_recipients_pinned_to_incident_time_authorization(self):
        self.scenario()
        g.draft(self.db, 'na-1', 'inc-1', 'tenant-a', *WINDOW, REF, ISSUE, UPDATE1)
        r = g.issue(self.db, 'na-1', ISSUE)
        # 11:49 换代前授权的联系人；既不是新联系人，也不是域名持有人
        self.assertEqual(r['recipients'], ['ops-a@example.com'])
        contacts = [x['contact'] for x in rows(self.db, 'SELECT * FROM incident_notice_recipients WHERE notice=?',
                                               ('na-1',))]
        self.assertNotIn('new-ops-a@example.com', contacts)
        self.assertNotIn('team-a', contacts)
        self.assertEqual(one(self.db, 'SELECT holder FROM claims WHERE host=?', ('edge.example',))['holder'], 'team-a')

    def test_delivery_requires_channel_receipt(self):
        self.scenario()
        g.draft(self.db, 'na-1', 'inc-1', 'tenant-a', *WINDOW, REF, ISSUE, UPDATE1)
        g.issue(self.db, 'na-1', ISSUE)
        # 邮件接口返回成功不等于送达：无回执不得记 delivered
        self.assertEqual(g.record_delivery(self.db, 'na-1', 'ops-a@example.com', 'delivered', T(11, 53))['decision'],
                         'receipt_required')
        self.assertEqual(one(self.db, 'SELECT status FROM incident_notices WHERE id=?', ('na-1',))['status'], 'issued')
        self.assertEqual(g.record_delivery(self.db, 'na-1', 'stranger@example.com', 'delivered', T(11, 53),
                                           receipt='x')['decision'], 'not_a_recipient')
        self.assertEqual(g.record_delivery(self.db, 'na-1', 'ops-a@example.com', 'delivered', T(11, 53),
                                           receipt='rcpt-1')['decision'], 'delivered')
        self.assertEqual(one(self.db, 'SELECT status FROM incident_notices WHERE id=?', ('na-1',))['status'],
                         'delivered')
        self.assertEqual(g.record_delivery(self.db, 'na-1', 'ops-a@example.com', 'delivered', T(11, 54),
                                           receipt='rcpt-2')['decision'], 'duplicate_delivery')

    def test_bounce_escalates_to_contract_backup(self):
        self.scenario()
        g.draft(self.db, 'nb-1', 'inc-1', 'tenant-b', *WINDOW, REF, ISSUE, UPDATE1)
        g.issue(self.db, 'nb-1', ISSUE)
        # 旧联系人的事故通道仍待确认 → 退信升级到合同约定的备用联系人
        r = g.record_delivery(self.db, 'nb-1', 'ops-b@example.com', 'bounced', T(11, 53))
        self.assertEqual(r['decision'], 'escalated')
        self.assertEqual(r['backup'], 'backup-b@example.com')
        self.assertEqual(g.record_delivery(self.db, 'nb-1', 'backup-b@example.com', 'delivered', T(11, 54),
                                           receipt='rcpt-9')['decision'], 'delivered')
        self.assertEqual(one(self.db, 'SELECT status FROM incident_notices WHERE id=?', ('nb-1',))['status'],
                         'delivered')

    def test_bounce_without_backup_is_undeliverable(self):
        g.register_contact(self.db, 'tenant-c', 'ops-c@example.com', 'email', 'primary', 0, 9999)
        g.add_evidence(self.db, 'c-acc-1', 'tenant-c', 'acceptance', T(11, 42), T(11, 42), detail='order-c-1')
        g.draft(self.db, 'nc-1', 'inc-1', 'tenant-c', *WINDOW, REF, ISSUE, UPDATE1)
        g.issue(self.db, 'nc-1', ISSUE)
        self.assertEqual(g.record_delivery(self.db, 'nc-1', 'ops-c@example.com', 'bounced', T(11, 53))['decision'],
                         'escalation_unavailable')
        self.assertEqual(one(self.db, 'SELECT status FROM incident_notices WHERE id=?', ('nc-1',))['status'],
                         'undeliverable')

    def test_late_payment_callback_forms_correction_not_rewrite(self):
        self.scenario()
        g.draft(self.db, 'nb-1', 'inc-1', 'tenant-b', *WINDOW, REF, ISSUE, UPDATE1)
        g.issue(self.db, 'nb-1', ISSUE)
        v1 = one(self.db, 'SELECT * FROM incident_notices WHERE id=?', ('nb-1',))
        self.assertNotIn('order-b-2', v1['body'])
        # 迟到回调到达后，旧草稿不得原地发出
        g.draft(self.db, 'nb-x', 'inc-1', 'tenant-b', *WINDOW, REF, T(11, 53), UPDATE1)
        self.assertEqual(g.issue(self.db, 'nb-x', T(11, 56))['decision'], 'stale_draft')
        # 迟到回调形成第 2 版更正，而不是改写第 1 版
        r = g.correct(self.db, 'nb-2', 'nb-1', T(11, 56), T(12, 40))
        self.assertEqual(r['decision'], 'correction_drafted')
        self.assertEqual((r['version'], r['instruction']), (2, g.PAUSE))
        g.issue(self.db, 'nb-2', T(11, 56))
        v2 = one(self.db, 'SELECT * FROM incident_notices WHERE id=?', ('nb-2',))
        self.assertIn('order-b-1', v2['body'])
        self.assertIn('order-b-2', v2['body'])
        self.assertIn('11:55', v2['body'])   # 回调的获知时间必须披露
        self.assertIn('第 1 版', v2['body'])
        # 第 1 版保持原文，“待核实”不得被伪装成当时已知
        after = one(self.db, 'SELECT * FROM incident_notices WHERE id=?', ('nb-1',))
        self.assertEqual(after['body'], v1['body'])
        self.assertEqual(after['instruction'], g.PAUSE)
        self.assertIn('待核实', after['body'])
        self.assertEqual(one(self.db, 'SELECT supersedes FROM incident_notice_links WHERE notice=?', ('nb-2',))['supersedes'],
                         'nb-1')
        # 更正链是线性的
        self.assertEqual(g.correct(self.db, 'nb-z', 'nb-1', T(11, 57), T(12, 40))['decision'], 'already_corrected')

    def test_trace_backfill_and_bank_verification_extend_version_chain(self):
        self.scenario()
        g.draft(self.db, 'nb-1', 'inc-1', 'tenant-b', *WINDOW, REF, ISSUE, UPDATE1)
        g.issue(self.db, 'nb-1', ISSUE)
        g.correct(self.db, 'nb-2', 'nb-1', T(11, 56), T(12, 40))
        g.issue(self.db, 'nb-2', T(11, 56))
        v2 = one(self.db, 'SELECT * FROM incident_notices WHERE id=?', ('nb-2',))
        # 追踪补齐（12:00 获知）→ 第 3 版
        r3 = g.correct(self.db, 'nb-3', 'nb-2', T(12, 1), T(12, 50))
        self.assertEqual(r3['decision'], 'correction_drafted')
        g.issue(self.db, 'nb-3', T(12, 1))
        v3 = one(self.db, 'SELECT * FROM incident_notices WHERE id=?', ('nb-3',))
        self.assertIn('12:00', v3['body'])
        self.assertIn('请求追踪', v3['body'])
        # 银行核实（12:20 获知）→ 第 4 版，指令从暂停转为可继续
        r4 = g.correct(self.db, 'nb-4', 'nb-3', T(12, 21), T(13, 0))
        self.assertEqual(r4['instruction'], g.CONTINUE)
        g.issue(self.db, 'nb-4', T(12, 21))
        v4 = one(self.db, 'SELECT * FROM incident_notices WHERE id=?', ('nb-4',))
        self.assertIn('已核实支付', v4['body'])
        self.assertIn('12:20', v4['body'])
        self.assertIn('请勿重复提交', v4['body'])
        # 先前各版保持原文
        self.assertEqual(one(self.db, 'SELECT body FROM incident_notices WHERE id=?', ('nb-2',))['body'], v2['body'])
        versions = [x['version'] for x in rows(self.db, 'SELECT version FROM incident_notices WHERE tenant=?'
                                                       ' ORDER BY version', ('tenant-b',))]
        self.assertEqual(versions, [1, 2, 3, 4])

    def test_unaffected_tenant_gets_no_correction(self):
        self.scenario()
        g.draft(self.db, 'na-1', 'inc-1', 'tenant-a', *WINDOW, REF, ISSUE, UPDATE1)
        g.issue(self.db, 'na-1', ISSUE)
        # 追踪补齐只涉及乙：甲没有新证据，不 churn 新版本
        self.assertEqual(g.correct(self.db, 'na-2', 'na-1', T(12, 1), T(12, 50))['decision'], 'no_new_evidence')
        self.assertEqual(len(rows(self.db, 'SELECT id FROM incident_notices WHERE tenant=?', ('tenant-a',))), 1)
        # 未发出的草稿不能被“更正”
        g.draft(self.db, 'na-9', 'inc-1', 'tenant-a', *WINDOW, REF, ISSUE, UPDATE1)
        self.assertEqual(g.correct(self.db, 'na-10', 'na-9', T(12, 1), T(12, 50))['decision'], 'not_issued')

    def test_unattributed_activity_forces_broad_action_order(self):
        self.scenario()
        # 缺口内出现无法归属租户的请求 → 受影响集合不确定
        g.add_evidence(self.db, 'u-1', None, 'request', T(11, 46), T(11, 48), detail='order-unknown')
        rec = g.recommend(self.db, *WINDOW, ISSUE)
        self.assertTrue(rec['broad_required'])
        # 定向“可继续”被暂缓；定向“暂停”仍然允许
        self.assertEqual(g.draft(self.db, 'na-1', 'inc-1', 'tenant-a', *WINDOW, REF, ISSUE, UPDATE1)['decision'],
                         'broad_order_required')
        self.assertEqual(g.draft(self.db, 'nb-1', 'inc-1', 'tenant-b', *WINDOW, REF, ISSUE, UPDATE1)['decision'],
                         'drafted')
        # 广泛行动令：内容通用、不含任何租户交易，发往所有合同联系人
        self.assertEqual(g.draft_broadcast(self.db, 'nbroad', 'inc-1', *WINDOW, REF, ISSUE, UPDATE1)['decision'],
                         'drafted')
        r = g.issue(self.db, 'nbroad', ISSUE)
        self.assertEqual(sorted(r['recipients']), ['ops-a@example.com', 'ops-b@example.com'])
        body = one(self.db, 'SELECT body FROM incident_notices WHERE id=?', ('nbroad',))['body']
        self.assertIn('暂停所有支付', body)
        self.assertNotIn('order-a-1', body)
        self.assertNotIn('order-b-1', body)
        self.assertNotIn('order-unknown', body)

    def test_failed_request_is_safe_retry_only_without_trace_gap(self):
        g.register_contact(self.db, 'tenant-d', 'ops-d@example.com', 'email', 'primary', 0, 9999)
        g.add_evidence(self.db, 'd-req-1', 'tenant-d', 'request', T(11, 41), T(11, 41), detail='order-d-1')
        g.add_evidence(self.db, 'gap-1', None, 'trace_gap', T(11, 44), T(11, 48), end_at=T(11, 47))
        # 窗口在缺口之前结束：请求确定未被处理，可安全重试
        r = g.draft(self.db, 'nd-1', 'inc-1', 'tenant-d', T(11, 40), T(11, 43), REF, ISSUE, UPDATE1)
        self.assertEqual(r['instruction'], g.RETRY)
        # 同一请求若其后有追踪缺口：可能在缺口内不可见地重试 → 必须暂停
        r2 = g.draft(self.db, 'nd-2', 'inc-1', 'tenant-d', *WINDOW, REF, ISSUE, UPDATE1)
        self.assertEqual(r2['instruction'], g.PAUSE)

    def test_evidence_and_schedule_validation(self):
        self.assertEqual(g.add_evidence(self.db, 'bad', 'tenant-a', 'request', T(11, 50), T(11, 40))['decision'],
                         'invalid_evidence')
        self.assertEqual(g.add_evidence(self.db, 'g2', None, 'trace_gap', T(11, 44), T(11, 48))['decision'],
                         'invalid_evidence')
        self.assertEqual(g.register_contact(self.db, 'tenant-x', 'c@x', 'email', 'owner', 0, 9)['decision'],
                         'invalid_contact')
        self.scenario()
        # 下次更新时间必须是将来
        self.assertEqual(g.draft(self.db, 'nx', 'inc-1', 'tenant-a', *WINDOW, REF, ISSUE, ISSUE)['decision'],
                         'invalid_schedule')
        # 无证据的租户不发通知
        self.assertEqual(g.draft(self.db, 'nz', 'inc-1', 'tenant-z', *WINDOW, REF, ISSUE, UPDATE1)['decision'],
                         'no_activity')


if __name__ == '__main__':
    unittest.main()
