# 入口域名交接裁定所

本地模拟共享入口网关的域名权属、证书交付与分段流量交接。三个入口分别管理域名租约和证明、包含 SAN 集合的证书订单及网关部署、切换计划和健康样本。数据保存在 SQLite，测试和演示不访问真实 DNS、CA 或集群。

```sh
python -m edgehandoff demo --db demo.sqlite
python -m edgehandoff replay --db demo.sqlite
python -m unittest discover -s tests -v
```

各入口可独立运行 `python -m edgehandoff ownership|certificate|cutover --db state.sqlite --fixture fixtures/<入口>_normal.json`，另有对应 `failure` 样例。三个正常样例按顺序在同一数据库执行时，域名证明与委托允许证书订单，部署确认允许切换计划；网关代次改变或健康样本失败会阻断推进。`replay` 将原始输入重新执行到空数据库并逐表比较状态。重新演示请使用新数据库路径。

## 燃油保管与结算（`edgehandoff/fuel_custody.py`）

`fuel_reserve.py` 的临时实现把司机签字的 200 升直接与最低值比较，无法支撑断电时长承诺。`fuel_custody.py` 把每笔实物交割拆成可复算的计量原件：

- `delivery` 记录车载表升数、读表温度、表具标称系数、封签和司机签字；签字只证明保管链，不证明到货量。
- `settle` 用罐前后液位、温度-体积修正、试机耗油、含水与不可抽取底量对账；`expected_fuel_l` 与 `observed_fuel_l` 都在合同基准温度上比较，量纲不一致的 100+200−20 只作为 `naive_ticket_sum_l` 留档。
- `reserve` 先扣除自由水、不可抽取底量和未验油质，再按试机实测油耗折算可供电小时；未验油质、油耗未知或低于最低储备都会判 `short`。
- `report` 把计量原件、供应商应付、环境释放范围、罐存与可运行小时分开列出。
- `calibrate` 在探头校准签出后重算供应商差额与漏失范围，但不改写原始交割行，也不改变罐内实物。
- `authorize_supply` 只有事故指挥（跨站调拨另需邻站授权与质量负责人）能决定补给量；校准未完成时补订量以实测缺口为上限。封签调拨必须同时满足本站在承诺和邻站自身最低储备，同一批油不能在两站重复计为 ready。
- `commit_hours` / `revise_commitment` 只承诺已验油质支撑的小时数；土壤检测确认的额外释放量会回撤已宣称的小时并触发客户通知。

```sh
python -B -m unittest tests.test_fuel_custody -v
```

`tests/test_fuel_custody.py` 覆盖热胀体积、探头失准、罐底含水、试机耗油、土壤渗漏和邻站调拨六段轨迹。
