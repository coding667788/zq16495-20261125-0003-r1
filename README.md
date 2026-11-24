# keychronicle

`keychronicle` 是一个完全离线的 Python 3.12 标准库工具，用于在凭据轮换、隔离、撤销和新公示证据出现后，重新审计已归档签批。

它回答两类问题：

- `audit BUNDLE --issued-at T --known-at K`：在公示时间截至 `K` 时，对每份签批给出达到独立签发者阈值的**最小可信见证**，或区分**确切拒绝**与**信息不足/不确定**。
- `diff BUNDLE --issued-at T --from-known-at K1 --to-known-at K2`：比较两个知识截面，列出首次失效的证据边/引用边、受影响的全部终端审批，以及多路因果中最短且有证据的解释。

不访问网络，不依赖第三方包；样例密钥和 HMAC 均为离线合成数据。

## 快速开始

Windows PowerShell / Git Bash 均可，统一使用 UTF-8 JSON：

```bash
python -m keychronicle audit fixtures\rotation_quorum\bundle.json \
  --issued-at 2026-01-10T00:00:00Z \
  --known-at 2026-02-01T00:00:00Z
```

目录形式也可以；目录中放 `bundle.json`，或分别放 `approvals.json`、`signatures.json`、`keys.json`、`revocations.json`、`quarantines.json`、`clearances.json`、`checkpoints.json`、`policy.json`。

撤销经共享审批多级传播的差异：

```bash
python -m keychronicle diff fixtures\revocation_shared\bundle.json \
  --issued-at 2026-01-10T00:00:00Z \
  --from-known-at 2026-01-20T00:00:00Z \
  --to-known-at   2026-02-01T00:00:00Z
```

将结果写入 UTF-8 文件：

```bash
python -m keychronicle audit BUNDLE --issued-at T --known-at K \
  --output audit.json --compact
```

也支持两个已经分别序列化的知识截面文件：

```bash
python -m keychronicle diff early-bundle.json late-bundle.json --issued-at T
```

若快照内没有 `known_at`，快照中出现的记录视为该截面全部可见；同一 BUNDLE 的早晚公示过滤仍优先使用 `--from-known-at/--to-known-at`。

生成一把新的合成 HMAC 样例密钥：

```bash
python -m keychronicle keygen --issuer-id alice --key-id alice-2026
```

## 核心判定规则

1. 每个 HMAC 签名绑定签批 ID、签发时刻、规范化内容和 `requires/references` 引用。
2. 同一 `issuer_id` 的多把轮换钥匙只产生一个独立票数；两把旧钥匙的有效期即使重叠，也不能凑成两票。
3. 只有 HMAC 正确、钥匙在签名时刻处于有效期、且没有适用撤销/未解除隔离的签名，才是可用见证。
4. 达到阈值后，按稳定签名 ID 选择恰好阈值个、字典序最小的独立签发者，形成 inclusion-minimal witness。
5. 引用的前置审批必须可信；前置审批被撤销/拒绝会沿反向引用图传播。共享前置只计算一次。
6. 引用环不会导致无限递归。工具用迭代 SCC 算法输出稳定环证据；没有冻结检查点锚点时，环内节点为不确定。
7. 所有通知按 `published_at` 决定某个 `known-at K` 是否可见；撤销的 `effective_at` / `retroactive_to` 决定追溯时刻。

### 状态分类

每份签批同时给出细粒度和粗粒度状态：

| 字段 | 值 | 含义 |
|---|---|---|
| `status` / `verdict` | `trusted` | 已有达阈值的最小可信见证，且引用依赖成立 |
| `status` / `verdict` | `rejected` | 有确切拒绝证据，如签批/检查点/前置审批被撤销或拒绝 |
| `status` / `verdict` | `uncertain` | 信息不足、隔离中、依赖未证明或无锚点环 |
| `decision` | `trusted` / `rejected` / `inconclusive` / `quarantined` | 更细的内部判定 |
| `classification` | `trusted` / `definite_rejection` / `insufficient_evidence` | 对应“可信 / 确切拒绝 / 信息不足” |

常见 `reason_code`：

- `threshold_witness`
- `below_threshold`
- `quarantined_witness`
- `approval_revoked`
- `frozen_checkpoint_rejected`
- `dependency_rejected`
- `dependency_unproven`
- `missing_referenced_approval`
- `unresolved_reference_cycle`

错误 HMAC、未知钥匙、签发者与钥匙不匹配、钥匙超出有效期会记录在 `signature_reports[].status` 中，例如 `invalid_hmac`、`unknown_key`、`issuer_mismatch`、`key_expired_or_not_valid`、`revoked`、`quarantined`。单个坏签名不会污染同一签发者/其他签发者的有效见证选择。

## Bundle JSON 格式

顶层示例：

```json
{
  "schema_version": "keychronicle-bundle/1",
  "threshold": 2,
  "issued_at": "2026-01-10T00:00:00Z",
  "known_at": "2026-02-01T00:00:00Z",
  "policy": { "terminal_ids": ["FINAL_A"] },
  "keys": [],
  "approvals": [],
  "signatures": [],
  "quarantines": [],
  "clearances": [],
  "revocations": [],
  "checkpoints": []
}
```

字段别名：

- 签批引用：`requires`，也接受 `references`、`prerequisites`、`depends_on`、`refs`。
- 终端审批：签批上的 `"terminal": true` / `"is_terminal": true`，或 `policy.terminal_ids`；若均未显式指定，则把没有任何其他签批引用的图下沉节点视为终端。
- HMAC 字段：`hmac`、`signature`、`value` 或 `mac`，使用十六进制。
- 钥匙密钥：`secret`（UTF-8）或 `secret_hex`。
- 撤销追溯时间：`effective_at`、`retroactive_to` 或 `retroactive_at`。
- 公示时间统一为 `published_at`；没有该字段的基础记录视为该知识截面已知。

完整可读样例见：

- `fixtures/manual/bundle.json`：手算 HMAC 夹具。
- `fixtures/rotation_quorum/bundle.json`：同一签发者两把重叠旧钥匙。
- `fixtures/quarantine/bundle.json`：隔离后解除，以及隔离确认后撤销。
- `fixtures/revocation_shared/bundle.json`：共享审批、多级传播、同一终端的长短两路解释。
- `fixtures/cycle_checkpoint/bundle.json`：稳定三环和冻结检查点解开的二环。

可用下面命令重新生成这些确定性夹具（HMAC 由标准库计算；一个测试会钉住手算常量）：

```bash
python tools\build_fixtures.py
```

## HMAC-SHA256 与手算示例

签名消息为四行 ASCII：

```text
keychronicle-hmac-sha256/v1
<approval-id>
<canonical-issued-at-UTC>
<sha256-of-canonical-signed-content>
```

被摘要的规范化内容包含 `id`、`issued_at`、`payload` 和排序后的 `requires`，使用：

```python
json.dumps(value, ensure_ascii=False, sort_keys=True,
           separators=(",", ":"), allow_nan=False).encode("utf-8")
```

`fixtures/manual/bundle.json` 中的 `HM-1`：

```json
{"action":"readme-hand-calc","amount":7}
```

其完整规范化签名内容是：

```json
{"id":"HM-1","issued_at":"2026-01-10T00:00:00Z","payload":{"action":"readme-hand-calc","amount":7},"requires":[]}
```

SHA-256：

```text
d393986e29ed83b52d02b3860573e7c070f64707305b1ecbf69d43360cef589c
```

因此 HMAC 输入为：

```text
keychronicle-hmac-sha256/v1
HM-1
2026-01-10T00:00:00Z
d393986e29ed83b52d02b3860573e7c070f64707305b1ecbf69d43360cef589c
```

使用样例密钥 `manual-sample-secret` 得到：

```text
e429776e780d6c86bff26bfc4c6871e11efd18f24a55fb066a44e7d54c8232df
```

`tests/test_hand_computed.py` 会钉住这个值，防止消息格式漂移。

## 时间语义

- `T = --issued-at`：默认签批/签名时刻；签批或签名单独提供 `issued_at` / `signed_at` 时使用各自时间。
- `K = --known-at`：知识截面。只有 `published_at <= K` 的通知和证据可见。
- 钥匙有效期：`valid_from <= 签名时刻 <= valid_to`（端点包含；未提供的边界视为开放）。
- 隔离区间：默认 `[start_at, end_at)`；区间内且在 `K` 前没有可见解除/确认证据的签名为 `quarantined`。
- 解除证据：`clearances` 中引用 `quarantine_id`，或指向同一 `target_type/target_id`。
- 确认/恶化证据：可见撤销；撤销的 `effective_at <= 被审计行为时刻` 时适用。
- Diff 中 `first_failure_at` 取撤销的追溯生效时间；`published_at` 决定它在哪两个知识截面之间首次可见。

因此，早公示复核可能看到 `trusted`，中间截面看到 `uncertain/quarantined`，晚截面可能因解除恢复为 `trusted`，或因确认撤销变成 `rejected`。

## 审批引用、共享前置和环

引用边写成：

```text
reference:<dependent>-><prerequisite>
```

例如 `reference:SHARED->ROOT` 表示 `SHARED` 依赖 `ROOT`。撤销在因果解释中沿反方向传播：

```text
ROOT -> SHARED -> TERMINAL_DIRECT
```

稳定环证据包含：

- `cycle_id` / `stable_digest`
- 排序后的全部 SCC 节点
- SCC 内部边
- 从最小节点开始、按最小后继稳定选出的 `representative_path`
- `canonical_path`

无论 JSON 输入顺序如何，同一个环都会得到相同路径和摘要。

冻结检查点格式：

```json
{
  "id": "cp-lock-x-frozen",
  "approval_id": "LOCK_X",
  "decision": "trusted",
  "frozen_at": "2026-01-12T00:00:00Z",
  "published_at": "2026-01-12T00:00:00Z",
  "witness": {"independent_issuer_count": 2},
  "digest": "sha256:<checkpoint_digest>"
}
```

若提供 `digest`，工具会排除 `digest` 字段本身后重新计算规范化 SHA-256。可信检查点可以作为无好基环的冻结锚点；但可见的拒绝检查点、适用撤销或已传播的确切拒绝仍优先。

## Diff 输出

`diff` 会分别构造 `K1`、`K2` 两个完整审计引擎，然后比较边状态：

- `first_failures`：`failed` 状态在区间内首次出现的边。
  - `causal_class = direct_evidence`：签批有效性撤销、检查点拒绝、签名/钥匙/签发者撤销等直接证据。
  - `causal_class = propagated_reference`：因前置审批被拒而失效的引用边。
- `new_uncertainties`：新进入 `uncertain` 的签名、有效性或引用边，例如隔离公示。
- `terminal_changes`：决策发生变化的全部终端审批。
- `affected_terminal_ids`：决策实际改变的终端集合。
- 每条直接失败包含 `affected_terminal_ids` 和每个终端的 `terminal_effects`。
- `best_explanation` 先选最少 `hops`，同长度再按节点路径、边 ID 和证据 ID 稳定取字典序最小者。

在撤销夹具中，`TERMINAL_MULTI` 同时有短路径和长路径，工具选择：

```text
ROOT -> SHARED -> SHORT -> TERMINAL_MULTI
```

而不是：

```text
ROOT -> SHARED -> LONG_1 -> LONG_2 -> TERMINAL_MULTI
```

## 十万签批的性能边界

实现避免对每个终端递归复制/重走全部证明子图：

- 图索引、通知目标索引和时间区间均缓存。
- 使用迭代 Kosaraju SCC 与拓扑顺序，避免 Python 递归深度和栈溢出。
- 每个签批只构造一次基础证明结果；共享前置通过 ID / `proof:<approval-id>` 引用共享。
- Diff 的终端可达性按 SCC 记忆并集合合并，不按父子重复 DFS。
- 最小见证只保留恰好阈值个签名 ID，不展开嵌套的完整前置证明；需要图结构时可由 `prerequisite_ids` 和 proof refs 还原。

复杂度主体为 `O(V + E + S)`，其中 `V` 是签批数、`E` 是引用数、`S` 是签名/HMAC 数；大型终端集合的输出序列化成本与 JSON 本身大小一致。

运行 10 万链式普通签批基准：

```bash
python tools\benchmark_100k.py 100000
```

测试中有对应的 10 万用例，断言 `_base_result` 恰好被调用 100000 次、100000 个证明节点各构造一次，并设置宽松的 60 秒线性完成护栏。

## 测试

```bash
python -m unittest discover -s tests -v
```

跳过 10 万性能测试：

```bash
# Git Bash
KEYCHRONICLE_SKIP_PERF=1 python -m unittest discover -s tests -v

# PowerShell
$env:KEYCHRONICLE_SKIP_PERF="1"; python -m unittest discover -s tests -v
```

## 设计边界

这是离线审计/建模工具，不是密钥管理服务。夹具中的 `secret` 是公开的样例材料；真实 HMAC 密钥不应提交到仓库。工具不会联网获取 CRL/OCSP、当前时间或外部信任根，所有事实均来自 BUNDLE 中按公示时间过滤的输入。
