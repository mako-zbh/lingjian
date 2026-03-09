# lingjian 网站安全监测工具

`lingjian` 是一个网站安全监测工具，包含黑链、违规内容、后门、死链检测，并针对误报做了规则引擎优化。

## 核心升级

- 名称与入口统一为 `lingjian`。
- 修复原始爬虫黑名单配置拼接问题。
- 外链白名单改为域名匹配（`host == domain` 或 `host.endswith(.domain)`），减少误过滤。
- 增加检测前归一化：HTML 实体、URL 编码、Unicode 转义、`fromCharCode`、Base64 片段解码。
- 规则支持 `severity` 与 `enabled`，结果新增置信度（`high/medium/low`）。
- 检测输出默认仅保留 `medium/high` 命中，降低单点弱特征误报。
- 后门检测升级为“多特征打分 + 二次验证 + 模板页抑制”，降低登录页/错误页误报。
- 全站扫描采用受控 BFS，限制最大页面数，避免无限扩散。

## 项目结构

- `lingjian.py`: 程序入口
- `framework/console.py`: CLI 参数控制
- `modules/task_console.py`: 扫描任务编排
- `modules/crawler.py`: 链接爬取与页面抓取
- `modules/rule_engine.py`: 规则匹配引擎
- `modules/response.py`: 检测结果汇总与输出
- `config/`: 配置、日志、数据库初始化
- `orm/rules.py`: 规则读取
- `lingjian.db`: 规则数据库（首次运行自动初始化）

## 运行方式

```bash
pip install -r requirements.txt
python3 lingjian.py
python3 lingjian.py -u https://example.com
python3 lingjian.py -u https://example.com -t AllSite_Scan
uv run --with requests python lingjian.py -u https://example.com -t HomePage_Scan
```

扫描类型：
- `HomePage_Scan`
- `SecondPage_Scan`
- `AllSite_Scan`
- `CustomPage_Scan`

## 注意

仅用于授权的安全检测场景。

## 输出汇总

扫描结果会优先输出“检测汇总”，包括：
- 总体风险等级（`info/low/medium/high`）
- 各模块告警数量（黑链/违规/后门/死链）
- 高/中置信度数量
- 问题 URL Top 列表

默认行为：
- 终端仅输出汇总与报告路径
- 完整明细自动写入 `reports/*.md`
