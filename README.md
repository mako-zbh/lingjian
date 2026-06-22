# lingjian 网站安全监测工具

`lingjian` 是一个基于规则引擎的网站安全监测 CLI 工具，面向授权安全检测场景，提供**黑链、违规内容、后门、死链**四大检测能力，并针对误报与性能做了深度优化。

## 核心特性

### 检测引擎

| 模块 | 描述 |
|------|------|
| 🔗 黑链检测 | 隐藏外链、恶意脚本混淆跳转、NCR 编码注入 |
| 🚪 后门检测 | WebShell 路径探测、多特征打分、二次验证、模板页抑制 |
| ⚠️ 违规检测 | 色情、赌博、违法交易等违规内容识别 |
| 💔 死链检测 | 超时/连接错误与 HTTP 状态码分类统计 |

### 关键优化

#### 从 Libra 借鉴并增强
- **浏览器级编码智能识别**：chardet 推测真实编码，直接从原始字节解码，解决中文站点 GBK/GB2312 声明错误的乱码问题。
- **Script 切片黑链检测**：提取 `<script>` 标签逐标签匹配，避免全页匹配噪声；>9999 字符的超长脚本（第三方库）自动跳过。
- **58 个 UA 池**：合并 Libra 的 55 个 Chrome UA + 原有 3 个现代 UA，每次启动随机选取，降低反爬检测风险。
- **百度蜘蛛自适应回退**：连续 3 次蜘蛛 UA 被拒后，后续请求直接使用普通浏览器 UA，避免无效重试。

#### 独立改进
- **五层解码管道**：HTML 实体 → URL 解码（2 轮） → Unicode 转义 → `fromCharCode` → Base64 片段，覆盖黑帽 SEO 常用编码技术。
- **置信度打分体系**：每条规则带 `severity`（1-3）+ 命中数加权 → 输出 `high/medium/low` 置信度，默认仅输出 medium 及以上。
- **后门检测三级降噪**：页面签名去重（同模板 ≥3 次抑制）+ 多特征打分（状态码/体长/关键词/匹配数）+ 按 score 排序优先二次验证（仅验证前 5 条最高分候选）。
- **后门子目录扩展探测**：从爬虫发现的同域内链中提取目录级 URL（上限 5 个 base），避免 Webshell 藏在 `/admin/`、`/blog/` 等子目录被漏检。
- **Script 判定加权打分**：混淆特征/危险操作/外链各计 2 分，总分 ≥3 即放过，避免 AND 逻辑导致的漏报。
- **页面签名加盖尾部抽样**：头 2000 + 尾 1000 字符 MD5，比仅取前 3000 字符更好区分同模板不同内容的页面。
- **死链分类**：区分 `timeout_or_error`（连接超时/拒绝）和 `http_error`（4xx/5xx），报告汇总显示分布。
- **指纹去重合并**：同类型+URL+置信度+证据的 MD5 指纹合并，多来源引用汇聚到单一告警。

### 性能改进
- **首页复用**：`crawl_links` 返回已抓取的页面数据，避免 `collect_web_data` 重复请求。
- **后门路径并发探测**：`ThreadPoolExecutor` 并发探测 30 条路径，串行 → 并发，等待时间从最坏 300s 降至数秒。
- **AllSite 早期去重**：`seen_fetch_urls` set 在采集阶段就拦截重复 URL，避免同一外链被数百个页面引用后重复抓取。
- **受控 BFS**：全站扫描上限 300 页，二级扫描上限 80 页，防止无限扩散。

---

## 架构

```
lingjian/
├── lingjian.py                  # 入口（单行，调 framework.console）
├── lingjian.db                  # SQLite 规则库（首次运行自动初始化）
├── requirements.txt             # requests>=2.25.0
│
├── framework/
│   └── console.py               # argparse CLI，解析 -u / -t
│
├── modules/
│   ├── task_console.py          # 任务编排：4 种扫描策略 + 链接来源合并 + BFS 调度
│   ├── crawler.py               # 爬虫：HTML 链接提取 + 编码修复 + 并发页面抓取
│   ├── rule_engine.py           # 规则引擎：解码管道 + 黑链/违规/后门检测 + 打分降噪
│   ├── response.py              # 结果汇总：报告生成（.md + .json）+ 终端摘要打印
│   └── http_client.py           # 线程本地 requests.Session（20 连接池）
│
├── config/
│   ├── db.py                    # DDL 建表 + 种子数据 + init_db()
│   ├── crawler.py               # 爬虫约束：文件类型黑名单、超时、线程数、页面数上限
│   ├── detection.py             # 检测阈值：最低置信度、短词抑制、探测/验证上限
│   ├── requests.py              # 58 个 UA 池 + 百度蜘蛛/普通请求头
│   ├── logging.py               # Python logging → lingjian.log
│   ├── proxies.py               # 代理配置（默认空）
│   └── banner.py                # ASCII art banner
│
├── orm/
│   └── rules.py                 # 规则快照：一次性加载所有规则到内存字典
│
├── tools/
│   ├── enhance_rules.py         # 补充高精度规则（幂等插入）
│   ├── migrate_from_libra.py    # 旧 Libra 数据库迁移
│   └── common.py                # 时间工具
│
├── tests/
│   ├── test_crawler.py
│   └── test_response.py
│
├── reports/                     # 扫描报告输出目录（.md + .json）
└── docs/
    └── saas_technical_plan.md
```

### 数据流

```
用户输入 URL + 类型
       │
  [console.py] CLI 解析
       │
  [task_console.py] 加载规则快照 → 按策略调度
       │
  ├─ crawl_links()    提取外链/内链 + 返回首页数据
  ├─ collect_web_data() 并发抓取所有页面
  │
  [response.py] build_response()
       │
  ├─ backdoor_find()    并发探测后门路径（支持子目录扩展）
  ├─ blacklink_find()   script 切片 + 全页多上下文匹配
  ├─ violative_find()   归一化匹配 + 短词抑制
  └─ dead link 分类     timeout/HTTP error
       │
  指纹去重 → 置信度过滤 → .md + .json 报告 → 终端汇总
```

---

## 快速开始

### 环境要求
- Python 3.7+
- SQLite（内置，无需安装）

### 安装

```bash
pip install -r requirements.txt
```

### 基础用法

```bash
# 显示 banner
python3 lingjian.py

# 快速扫描首页（默认 HomePage_Scan）
python3 lingjian.py -u https://example.com

# 指定扫描类型
python3 lingjian.py -u https://example.com -t SecondPage_Scan
python3 lingjian.py -u https://example.com -t AllSite_Scan
python3 lingjian.py -u https://example.com/path/page -t CustomPage_Scan
```

### 扫描类型

| 类型 | 说明 | 页面数上限 |
|------|------|-----------|
| `HomePage_Scan` | 仅首页 + 外链 | 不限 |
| `SecondPage_Scan` | 首页 + 站内链接的二级页面 | 80 |
| `AllSite_Scan` | BFS 全站爬取 | 300 |
| `CustomPage_Scan` | 单页面 + 外链 | 不限 |

---

## 配置说明

### 爬虫配置 (`config/crawler.py`)

```python
FILE_TYPE_BLACKLIST = [...]   # 不抓取的文件类型（css/jpg/pdf/exe 等）
SCHEME_BLACKLIST = [...]      # 不抓取的协议（mailto/javascript/data:image）
REQUEST_TIMEOUT = 10          # HTTP 超时（秒）
MAX_WORKERS = 20              # 并发线程数
MAX_ALLSITE_PAGES = 300       # 全站扫描上限
MAX_SECONDPAGE_PAGES = 80     # 二级扫描上限
```

### 检测配置 (`config/detection.py`)

```python
MIN_CONFIDENCE = 'medium'           # 输出最低置信度（low/medium/high）
MIN_SHORT_TOKEN_HITS = 2            # 短词抑制阈值（≤2字符规则需命中≥2次）
MAX_BACKDOOR_PROBES = 30            # 后门路径探测上限
MAX_BACKDOOR_SECONDARY_CHECKS = 5   # 二次验证上限（按 score 降序取 top-N）
```

### 代理配置 (`config/proxies.py`)

```python
PROXIES = {
    'http': 'http://proxy.server:port',
    'https': 'https://proxy.server:port',
}
```

### 规则管理

规则存储在 `lingjian.db`（SQLite），首次运行自动建表并写入种子规则。提供两个运维工具：

```bash
# 从旧 Libra 系统迁移规则
python3 tools/migrate_from_libra.py

# 补充高精度规则（幂等插入，不会重复）
python3 tools/enhance_rules.py
```

数据库包含 5 张表：`blacklink_rules`、`backdoor_rules`、`backdoor_paths`、`violativelink_rules`、`whiteips`。所有规则均支持 `severity`（1-3）和 `enabled`（0/1）字段。

---

## 报告输出

每次扫描生成双格式报告：

```
reports/
├── 20250618_143022_https_example_com.md   # Markdown 明细报告
└── 20250618_143022_https_example_com.json # 结构化 JSON 数据
```

### 终端输出示例

```
------------------------------------------------------------
# 检测地址：https://example.com
------------------------------------------------------------
### 检测汇总

任务类型：HomePage_Scan
检测时间：2025-06-18 14:30:22
总体风险：medium
黑链告警：2 (高:1 中:1 URL:2)
违规告警：0 (高:0 中:0 URL:0)
后门告警：0 (高:0 中:0 URL:0)
死链数量：3 (URL:3) [超时:1 HTTP错误:2]
问题URL Top3:
- https://example.com (2)
- https://example.com/old-page (1)
详细报告(Markdown)：reports/20250618_143022_https_example_com.md
------------------------------------------------------------
```

---

## 运行测试

```bash
python3 -m pytest tests/ -v
```

---

## 更新日志

### v2.0（当前）
- 集成 Libra 编码智能识别（`resp.content.decode(apparent_encoding)`）
- Script 切片黑链检测 + 加权打分判定（替代 AND 逻辑）
- 58 个 UA 池 + 百度蜘蛛自适应回退
- 后门路径并发探测 + score 降序二次验证 + 子目录扩展
- 首页抓取数据复用，避免重复 HTTP 请求
- AllSite BFS 早期去重
- 页面签名加盖尾部抽样
- 死链分类（超时/HTTP 错误）+ 后门评分惩罚项增强
- 违规 snippet 改为匹配文本（而非正则模式）

### v1.0
- 初始版本：lingjian 从 Libra fork，独立命名与入口
- 规则引擎重构：severity/enabled、置信度、多上下文解码
- 后门检测：多特征打分 + 二次验证 + 模板页抑制
- 受控 BFS 全站扫描
- 双格式报告输出

---

## 许可与免责

MIT License。本工具**仅用于授权的安全检测场景**，使用者需自行承担使用风险。
