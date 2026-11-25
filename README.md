# 入口域名交接裁定所

本地模拟共享入口网关的域名权属、证书交付与分段流量交接。三个入口分别管理域名租约和证明、包含 SAN 集合的证书订单及网关部署、切换计划和健康样本。数据保存在 SQLite，测试和演示不访问真实 DNS、CA 或集群。

```sh
python -m edgehandoff demo --db demo.sqlite
python -m edgehandoff replay --db demo.sqlite
python -m unittest discover -s tests -v
```

各入口可独立运行 `python -m edgehandoff ownership|certificate|cutover --db state.sqlite --fixture fixtures/<入口>_normal.json`，另有对应 `failure` 样例。三个正常样例按顺序在同一数据库执行时，域名证明与委托允许证书订单，部署确认允许切换计划；网关代次改变或健康样本失败会阻断推进。`replay` 将原始输入重新执行到空数据库并逐表比较状态。重新演示请使用新数据库路径。
