# 接入检查清单（10 条）

给接 opcpay / 即刻收这类「购买 + 权益 + 核销」网关的团队。每条都对应本仓库里一个能变红的场景，不是泛泛建议。

| # | 检查项 | 通过判据 | 常见错法 | 对应场景 |
|---|---|---|---|---|
| 1 | 幂等键非空且持久化 | purchase/consume 发出前键已落盘；空键在客户端就被拒绝 | 空字符串被 JSON 序列化丢掉，重试变成新单 | C1 / N4 / E4 |
| 2 | 金额由服务端决定 | 请求里没有价格，或价格只作展示；0/负/NaN/超大一律 400 | 信任客户端 `amount`，或只在前端校验 | C2 / E2 / E7 |
| 3 | 购买 ≠ 已支付 | 只有 `transactions/query` 或权益查询返回 `PAID`/`ALLOW` 才发货 | 把 `purchase.status=READY` 当成功 | N6 / E5 |
| 4 | 未知状态不猜 | `PENDING`/`UNKNOWN`/404 不发货、不重建订单；原幂等键重查 | 未知就新建一笔，造成双扣 | E5 / A5 |
| 5 | 核销原子且幂等 | 并发 N 次只成功 1 次；同键重试返回同一结果 | 先读余额、再扣减，中间无锁 | E3 / N4 |
| 6 | webhook 验签完整 | 校验 `yirenfu-timestamp` 10–12 位、`v1=` 64 hex、HMAC(ts.body)、300s、event.id 与头一致 | 只比对长度，或把 body 重新序列化后验签 | A3 / W2 |
| 7 | webhook 重放去重 | 已见 event id 落库；重复投递不重复记账 | 只验签不去重，重试即多扣一次 | A4 / W3 / C3 |
| 8 | 回调 URL 白名单 | 只接受 HTTPS + 公网主机；拒绝 localhost/私网/169.254.169.254 | 直接 `requests.get(callback_url)`，可被 SSRF | A1 / W1 |
| 9 | 租户隔离 | 所有查询/核销带 `(api_key, user_id)`；跨租户返回 404 而非他人数据 | 只按 user_id 查，A 能看到 B 的订单 | A5 / A6 |
| 10 | 退款与权益回收分开 | 支付退款成功后再决定是否撤权益；撤销本身幂等 | 退款回调里直接扣额度，重复回调扣两次 | E6 |

补充三条运维项：

- 记录 `request_id`、`error_code`、`retryable`：线上 401 的响应体已经带这三个字段，排障时先留 `request_id`。
- 查询限速：官方建议交易查询 ≥15s 一次、每凭证 120 次/分钟；批量对账要排队，不要并发轰。
- 锁 SDK 版本：`opcpay@0.3.5` 与 0.2.x 有破坏性差异（0.2 删了 env 回退与兼容别名）；升级前跑 `make sdk`。

自检命令：

```bash
cd agentpaybench
python3 webhook_e2e.py          # W1–W4：注册/轮换/重试/禁用
python3 client_guard_selftest.py # C1–C3：幂等键/金额/重放
python3 stress.py --threads 50   # E3：并发核销
python3 selftest.py              # 20 场景 + naive 变异证明
```
