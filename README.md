# 入口域名交接裁定所

本地模拟共享入口网关的域名权属、证书交付与分段流量交接。三个入口分别管理域名租约和证明、包含 SAN 集合的证书订单及网关部署、切换计划和健康样本。数据保存在 SQLite，测试和演示不访问真实 DNS、CA 或集群。

```sh
python -m edgehandoff demo --db demo.sqlite
python -m edgehandoff replay --db demo.sqlite
python -m unittest discover -s tests -v
```

各入口可独立运行 `python -m edgehandoff ownership|certificate|cutover --db state.sqlite --fixture fixtures/<入口>_normal.json`，另有对应 `failure` 样例。三个正常样例按顺序在同一数据库执行时，域名证明与委托允许证书订单，部署确认允许切换计划；网关代次改变或健康样本失败会阻断推进。`replay` 将原始输入重新执行到空数据库并逐表比较状态。重新演示请使用新数据库路径。

## 服务补偿结算（settlement）

`sla_claim.draft` 只用不健康样本数乘费率，样本里既没有客户请求也没有付款事实，单个坏样本就会出钱。`sla_settlement` 改以核赔原件（入口请求、网关接受回单、收银确认、客户订单、旧后端回放日志、银行清算回单）为事实来源：

- 重试链（含多层嵌套重试）按订单号归并为一次购买；只有服务窗内网关已接受、且最终无任何付款证据的订单才进入 `claimable`，坏样本无请求不赔，健康样本下的丢单仍赔。所有证据按商户隔离，同订单号跨商户互不可见；回放引用的清算号必须属于本订单。
- 旧后端自称成功但无银行清算号的补报一律 `sealed` 封存待银行对账；附清算号或收银成功的订单视为已成交而 `rejected`；银行 `paid=0` 的明确裁决可推翻陈旧的收银成功。
- 同一商户重叠服务窗的第二个案件在立案即被拒绝，一笔购买最多赔一次；两种互斥兑现路径也不可叠加。
- 两种互斥兑现路径：`proven_first` 当天只赔可证明损失、争议笔只提准备金（不占用现金）；`cap_advance` 须先取得商户签署的临时保全承诺，平台在封顶内垫付，垫付款记为平台债权，资金占用由平台承担，次月清算退回多付。
- 资金只通过不可变的双边分录（`ledger_entries`）移动：已支付抵扣、待核赔、退票重付分簿记账；补证到达只追加当期更正分录（损失冲回并确认追回应收、垫付转损失、准备金释放），永不改写旧发票，每订单独立更正发票、重复裁决不重复过账；退票经冲回后可向新账户重付，但重付前重新核验资格，已追回/已退款订单不得复活。
- `trace_payment`/`trace_request` 可从任意赔款反查客户请求、完整重试链、购买结果与真实银行付款（原付/冲回/重付全链）；销户、换账户、退款、退票、跨月调账与切流回滚均为事件，可整体 `replay`。

```sh
python -m edgehandoff settlement --db state.sqlite --fixture fixtures/settlement_dispute.json
```

