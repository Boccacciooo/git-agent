# Git仓库自动化运维与代码质量管控Agent

一个基于LangChain + PyGithub + Flask实现的Git仓库自动化运维系统，采用多Agent协作架构，提供PR自动审核、Issue智能处理、技术债监控和版本自动发布功能。

## ✨ 功能特性

- 🤖 **PR自动审核**：代码规范检查、安全漏洞扫描、测试覆盖率统计
- 📋 **Issue智能处理**：自动分类、打标签、分配负责人、常见问题回复
- 📊 **技术债监控**：每周自动扫描代码库，生成结构化技术债报告
- 🚀 **版本自动发布**：自动生成更新日志，创建GitHub Release
- 🔒 **安全可靠**：Webhook签名验证，防止伪造请求

## 🚀 快速部署

### 1. 准备工作

1. 创建GitHub个人访问令牌（需要`repo`和`admin:repo_hook`权限）
2. 获取OpenAI API Key（或其他兼容OpenAI接口的LLM服务）
3. 准备一台可以访问GitHub和OpenAI的Linux服务器

### 2. 部署步骤

1. **克隆仓库到服务器**
   ```bash
   git clone https://github.com/你的用户名/git-agent.git
   cd git-agent