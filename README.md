# 神机 (ShenJi) 🔮

> 基于 LLM + LangGraph 的智能渗透测试 Agent，支持持续推理循环和动态工具选择
>
> *"神机妙算，攻无不克"*

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![LangGraph](https://img.shields.io/badge/LangGraph-2.0+-green.svg)](https://github.com/langchain-ai/langgraph)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ⚠️ 法律声明

**本系统仅限合法授权场景使用！**

- 未经授权对他人系统进行渗透测试属于违法行为
- 使用者需遵守当地法律法规
- 开发者不承担任何滥用责任

## ✨ 核心特性

### 🧠 SmartAgent (基于 LangGraph，推荐)

| 特性 | 描述 |
|------|------|
| 🔄 **持续推理循环** | 每次工具执行后都能重新分析决策，不断优化策略 |
| 📊 **状态累积** | 端口、路径、漏洞信息自动累积，参与后续决策 |
| 🎯 **智能工具选择** | LLM 基于完整上下文动态选择最合适的工具 |
| 🛑 **自动停止** | 找到 Flag 或完成目标时自动结束 |
| 🔀 **条件分支** | 根据结果智能选择下一步，支持多种执行路径 |

### 📋 传统模式 (兼容)

| 特性 | 描述 |
|------|------|
| 🔐 **人工确认机制** | 每一步操作都需要人类专家确认，确保安全可控 |
| 📊 **实时进度显示** | 使用 Rich 库显示美观的进度条和执行状态 |
| 📚 **知识库驱动** | 集成 PayloadsAllTheThings 知识库，提供专业指导 |
| 🔧 **工具即插即用** | 直接调用系统已安装的安全工具，无需重新封装 |

## 🏗️ 系统架构

### SmartAgent 工作流 (LangGraph)

```
                    ┌─────────────┐
                    │   START     │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
           ┌────────│   PLANNER   │◄────────┐
           │        └──────┬──────┘         │
           │               │                │
           │    ┌──────────┼──────────┐     │
           │    │          │          │     │
           │    ▼          ▼          ▼     │
           │ ┌──────┐ ┌──────┐ ┌──────┐    │
           │ │ HTTP │ │ NMAP │ │ENUMER│    │
           │ └──┬───┘ └──┬───┘ └──┬───┘    │
           │    │        │        │        │
           │    └────────┴────────┘        │
           │               │                │
           │               ▼                │
           │        ┌─────────────┐         │
           │        │   ANALYZER  │─────────┘
           │        └──────┬──────┘
           │               │
           │               ▼
           │        ┌─────────────┐
           └───────►│     END     │
                    └─────────────┘
```

### 系统分层

```
┌─────────────────────────────────────────────────────────────┐
│                    神机 (ShenJi) v2.0                       │
├─────────────────────────────────────────────────────────────┤
│  展示层    │  CLI + Rich UI + 人工确认交互界面              │
├─────────────────────────────────────────────────────────────┤
│  控制层    │  LangGraph StateGraph + 节点调度器             │
├─────────────────────────────────────────────────────────────┤
│  智能层    │  Planner(决策) + Analyzer(分析) + LLM         │
├─────────────────────────────────────────────────────────────┤
│  工具层    │  HTTP/Nmap/Gobuster/Nuclei/Nikto              │
├─────────────────────────────────────────────────────────────┤
│  基础设施  │  状态管理 + 配置系统 + 日志记录                │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 快速开始

### 1. 环境要求

- Python 3.10+
- 操作系统：Linux (推荐 Kali Linux) / macOS / Windows (WSL)

### 2. 安装依赖

```bash
# 克隆项目
git clone https://github.com/your-repo/shenji-agent.git
cd shenji-agent

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# 安装依赖
pip install -r requirements.txt
```

### 3. 配置

```bash
# 复制环境变量模板
cp .env.example .env

# 编辑配置文件，填入你的 API Key
vim .env
```

### 4. 运行

```bash
# 使用 神机Agent (推荐)
python main.py http://target.com --strategy smart --auto

# 或直接运行
python -m agent.smart_agent http://target.com --auto

# 使用传统模式
python main.py http://target.com --strategy standard
```

## 📖 使用示例

### 神机Agent 智能模式

```bash
$ python main.py http://docker.lan:8080 --strategy smart --auto

╭─────────────────────────────────────────────────────────────╮
│           🔮 神机 (ShenJi)                                   │
│           智能渗透测试 Agent v2.0.0                          │
│           "神机妙算，攻无不克"                                │
╰─────────────────────────────────────────────────────────────╯

Target: http://docker.lan:8080

[Planner] 下一步: http
✓ [http] 状态码: 200, 标题: CTF Challenge, 表单: 2, 链接: 15
[Analyzer] 发现 CTF 线索: hidden, admin, flag

[Planner] 下一步: gobuster
✓ [gobuster] 发现 8 个有效路径

[Planner] 下一步: nmap
✓ [nmap] 发现端口: 22, 80, 3306

🚩🚩🚩 FLAG 已找到！🚩🚩🚩
╭──────────────────────────────────╮
│  flag{smart_agent_success}       │
╰──────────────────────────────────╯
```

### 传统交互式模式

```bash
$ python main.py 192.168.1.100

📋 执行计划:
  Step 1: HTTP 内容获取和分析
  Step 2: 端口扫描 (Nmap)
  Step 3: 目录枚举 (Gobuster)

🤔 是否批准此计划？ [Y/n]: y

┌─────────────────────────────────────────────────────────────┐
│  🔒 等待确认                                                 │
│  Step 1/3: HTTP 内容获取                                    │
│  命令: http_request http://192.168.1.100                   │
│  风险: 🟢 低                                                │
│  🤔 执行此命令？ [Y/n/m/d/s/a]: y                           │
└─────────────────────────────────────────────────────────────┘
```

### 命令行参数

| 参数 | 说明 |
|------|------|
| `target` | 目标地址 (URL/IP/domain:port) |
| `--strategy, -s` | 测试策略: `smart`(推荐), `standard`, `recon`, `scan`, `full` |
| `--auto, -a` | 自动模式，无需用户确认 |
| `--config, -c` | 配置文件路径 |
| `--max-attempts, -m` | 最大尝试次数 (SmartAgent) |

## 🔧 支持的工具

| 工具 | 类别 | 神机Agent | 传统模式 |
|------|------|:----------:|:--------:|
| HTTP | 信息收集 | ✅ | ✅ |
| Nmap | 端口扫描 | ✅ | ✅ |
| Gobuster | 目录枚举 | ✅ | ✅ |
| Nuclei | 漏洞扫描 | ✅ | ✅ |
| Nikto | Web扫描 | ✅ | ✅ |

## 📁 项目结构

```
agent/
├── core/
│   ├── state.py          # LangGraph 状态定义
│   ├── graph.py          # 工作流图构建
│   ├── nodes/            # 节点实现
│   │   ├── planner.py    # 规划节点 (LLM决策)
│   │   ├── executor.py   # 执行节点 (工具执行)
│   │   └── analyzer.py   # 分析节点 (结果处理)
│   ├── models.py         # 数据模型
│   └── ...
├── tools/                # 工具包装器
│   ├── http.py           # HTTP 工具
│   ├── nmap.py           # Nmap 扫描
│   ├── gobuster.py       # 目录枚举
│   ├── nuclei.py         # 漏洞扫描
│   └── nikto.py          # Web 扫描
├── llm/
│   └── provider.py       # LLM 提供者
├── pentest_agent.py      # 传统入口 (兼容)
└── smart_agent.py        # 神机Agent 入口 (推荐)

main.py                   # 主程序入口
config.yaml               # 配置文件
.env.example              # 环境变量模板
```

## 🔄 神机Agent vs 传统模式

| 特性 | 神机Agent | 传统模式 |
|------|:----------:|:--------:|
| 决策方式 | LLM 持续推理 | 预定义计划 |
| 执行流程 | 动态调整 | 固定步骤 |
| 状态管理 | 自动累积 | 手动追踪 |
| Flag 检测 | 多节点检测 | 单点检测 |
| 错误恢复 | 智能重试 | 人工干预 |
| 适用场景 | CTF/自动化测试 | 精细控制/审计 |

## 🤝 贡献

欢迎贡献代码、报告问题或提出建议！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

- [LangChain](https://github.com/langchain-ai/langchain) - LLM 应用框架
- [LangGraph](https://github.com/langchain-ai/langgraph) - Agent 工作流框架
- [Rich](https://github.com/Textualize/rich) - 终端 UI 库
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - 安全知识库
- 所有安全工具的开发者们

---

<div align="center">
  <sub>⚠️ 请确保仅在合法授权的场景下使用本系统</sub>
</div>
