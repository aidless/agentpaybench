# 发布清单（未执行）

当前状态：本地文件完整、29 项自检与 SDK 探针全绿；**没有** `git init`、commit、
远端仓库或 push。建远端与推送需要一次明确授权（仓库名/可见性/owner）。

## 发布前必过

```bash
cd agentpaybench
ruff check .
python3 all_selftest.py              # 29 hardened pass / naive 23 fail
python3 fuzz_invariants.py --steps 1000
python3 fuzz_invariants.py --mode naive --steps 500
python3 stress.py --threads 50
python3 runner.py --json report.json
make sdk OPCPAY_SDK=/tmp/opcpay-audit/package/index.mjs   # 19/19
python3 -m pip wheel . --no-deps --no-build-isolation
```

## 建议仓库

- owner/name：`aidless/agentpaybench`（或你的个人账号）
- 可见性：public（基准要能被复现）；若含内部数据则 private
- 描述：`A 20-scenario robustness benchmark for agent payment / entitlement APIs`
- topics：`agent`, `payments`, `benchmark`, `idempotency`, `webhook`, `security`

## 建仓与推送（需授权后执行）

```bash
cd agentpaybench
git init -b main
git add .
git commit -m "AgentPayBench 0.3.0: 20 server scenarios, client guards, webhook lifecycle, fuzz, rate limits"
gh repo create aidless/agentpaybench --public --source . --remote origin --push
```

> 本目录位于工作区仓库内；上面的 `git init` 会建一个**嵌套**独立仓库。若想保留在
> 工作区历史里，改用 `git subtree split --prefix=agentpaybench -b agentpaybench-standalone`
> 再推该分支，避免嵌套。

## CI badge

```markdown
[![ci](https://github.com/aidless/agentpaybench/actions/workflows/ci.yml/badge.svg)](https://github.com/aidless/agentpaybench/actions/workflows/ci.yml)
```

## 真实沙箱对账（未执行）

需要 opcpay 测试商户的 `apiKey`（`opcpay_api_key`），且会产生真实小额支付：

1. 用测试 key 设 `Authorization: Bearer ...`，先 `GET /capabilities` 确认
   `transaction_query`/`refund` 能力位。
2. `GET /product` 只读对齐 SKU 与价格。
3. 买最便宜的次数包，走完 `READY → 支付 → PENDING/PAID → access → consume`，
   记录 `request_id` 与 9 字段状态响应。
4. 对账三条：服务端价 = 目录价；`UNKNOWN` 不发货；退款后 `access` 必须 `DENY`。
5. 全程只对测试商户，不碰生产 key；结束后把订单号与差异写进 `notes/`。

没有 key 时这一项保持“未执行”，不要用 mock 结果冒充真实对账。
