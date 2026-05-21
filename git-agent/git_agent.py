import os
import tempfile
import subprocess
import hmac
import hashlib
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from github import Github, GithubException
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from apscheduler.schedulers.background import BackgroundScheduler

# -------------------------- 配置加载 --------------------------
load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
REPO_NAME = os.getenv("REPO_NAME")
MAIN_BRANCH = os.getenv("MAIN_BRANCH", "main")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-3.5-turbo-1106")
BUG_ASSIGNEE = os.getenv("BUG_ASSIGNEE")
DOCS_ASSIGNEE = os.getenv("DOCS_ASSIGNEE")
PORT = int(os.getenv("PORT", 5000))

# 初始化客户端
app = Flask(__name__)
github_client = Github(GITHUB_TOKEN)
repo = github_client.get_repo(REPO_NAME)
llm = ChatOpenAI(
    model=LLM_MODEL,
    temperature=0.1,
    api_key=OPENAI_API_KEY,
    base_url=OPENAI_BASE_URL
)
scheduler = BackgroundScheduler(timezone="Asia/Shanghai")

# -------------------------- 工具函数 --------------------------
def verify_webhook_signature(request):
    """验证GitHub Webhook签名，防止伪造请求"""
    signature_header = request.headers.get("X-Hub-Signature-256")
    if not signature_header:
        return False
    
    sha_name, signature = signature_header.split("=")
    if sha_name != "sha256":
        return False
    
    mac = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode("utf-8"),
        msg=request.data,
        digestmod=hashlib.sha256
    )
    return hmac.compare_digest(mac.hexdigest(), signature)

def clone_repo_to_temp(branch_name):
    """克隆指定分支到临时目录"""
    temp_dir = tempfile.mkdtemp()
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch_name, 
             f"https://{GITHUB_TOKEN}@github.com/{REPO_NAME}.git", temp_dir],
            check=True,
            capture_output=True,
            text=True,
            timeout=120
        )
        return temp_dir
    except subprocess.CalledProcessError as e:
        print(f"克隆分支失败: {e.stderr}")
        subprocess.run(["rm", "-rf", temp_dir], capture_output=True)
        raise

# -------------------------- 核心Agent实现 --------------------------
class PRAuditAgent:
    """PR自动审核Agent：代码规范+安全漏洞+测试覆盖率检查"""
    
    def __init__(self):
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", "你是一位资深的代码审核专家。请根据以下代码检查结果，生成专业、友好、可执行的审核意见。"
                      "分点列出问题，按严重程度排序（严重/警告/建议），并给出具体的修改建议。"
                      "如果没有问题，给出通过审核的结论。"
                      "保持语言简洁，重点突出。"),
            ("human", "代码规范检查结果：\n{pylint_result}\n\n"
                     "安全漏洞检查结果：\n{bandit_result}\n\n"
                     "测试覆盖率：{coverage}%\n\n"
                     "PR标题：{pr_title}\nPR描述：{pr_description}")
        ])
        self.chain = self.prompt | llm | StrOutputParser()
    
    def run_code_checks(self, temp_dir):
        """运行代码质量检查工具"""
        results = {}
        
        # 1. Pylint代码规范检查
        try:
            pylint_output = subprocess.run(
                ["pylint", temp_dir, "--rcfile=config/pylintrc", "--output-format=text"],
                capture_output=True,
                text=True,
                timeout=60
            )
            results["pylint"] = pylint_output.stdout if pylint_output.stdout else "✅ 无代码规范问题"
        except subprocess.TimeoutExpired:
            results["pylint"] = "⚠️ 代码规范检查超时"
        except Exception as e:
            results["pylint"] = f"❌ 代码规范检查失败: {str(e)}"
        
        # 2. Bandit安全漏洞检查
        try:
            bandit_output = subprocess.run(
                ["bandit", "-r", temp_dir, "-c", "config/bandit.yaml", "-f", "text"],
                capture_output=True,
                text=True,
                timeout=60
            )
            results["bandit"] = bandit_output.stdout if bandit_output.stdout else "✅ 无安全漏洞"
        except subprocess.TimeoutExpired:
            results["bandit"] = "⚠️ 安全漏洞检查超时"
        except Exception as e:
            results["bandit"] = f"❌ 安全漏洞检查失败: {str(e)}"
        
        # 3. 测试覆盖率检查
        results["coverage"] = 0.0
        if os.path.exists(os.path.join(temp_dir, "tests")):
            try:
                subprocess.run(
                    ["coverage", "run", "--source", temp_dir, "-m", "pytest", os.path.join(temp_dir, "tests")],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                coverage_output = subprocess.run(
                    ["coverage", "report", "-m"],
                    capture_output=True,
                    text=True
                )
                for line in coverage_output.stdout.splitlines():
                    if "TOTAL" in line:
                        coverage_percent = line.split()[-1].replace("%", "")
                        results["coverage"] = float(coverage_percent)
                        break
            except Exception as e:
                print(f"测试覆盖率检查失败: {e}")
        
        return results
    
    def process_pr(self, pr_number):
        """处理单个PR"""
        try:
            pr = repo.get_pull(pr_number)
            if pr.state != "open":
                return
            
            # 添加正在审核的标签
            pr.add_to_labels("🤖 AI审核中")
            
            # 克隆PR分支
            temp_dir = clone_repo_to_temp(pr.head.ref)
            
            # 运行代码检查
            check_results = self.run_code_checks(temp_dir)
            
            # 生成AI审核意见
            ai_comment = self.chain.invoke({
                "pylint_result": check_results["pylint"],
                "bandit_result": check_results["bandit"],
                "coverage": check_results["coverage"],
                "pr_title": pr.title,
                "pr_description": pr.body or "无描述"
            })
            
            # 评论到PR
            comment = f"# 🤖 AI自动代码审核报告\n\n{ai_comment}\n\n"
            comment += f"## 📊 统计信息\n"
            comment += f"- 测试覆盖率：**{check_results['coverage']}%**\n"
            comment += f"- 审核时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            comment += "---\n*本报告由Git自动化运维Agent自动生成*"
            pr.create_issue_comment(comment)
            
            # 移除审核中标签，添加结果标签
            pr.remove_from_labels("🤖 AI审核中")
            if check_results["coverage"] < 50:
                pr.add_to_labels("📉 低测试覆盖率")
            if "严重" in ai_comment:
                pr.add_to_labels("❌ 需要修改")
            else:
                pr.add_to_labels("✅ AI审核通过")
            
        except GithubException as e:
            print(f"处理PR #{pr_number} 失败：{e}")
        except Exception as e:
            print(f"处理PR #{pr_number} 发生未知错误：{e}")
        finally:
            # 清理临时目录
            subprocess.run(["rm", "-rf", temp_dir], capture_output=True)

class IssueAgent:
    """Issue智能处理Agent：自动分类+打标签+分配负责人+常见问题回复"""
    
    def __init__(self):
        self.classify_prompt = ChatPromptTemplate.from_messages([
            ("system", "你是一个Issue分类专家。请根据Issue的标题和描述，将其分类为以下类型之一："
                      "bug, feature, question, documentation, enhancement。"
                      "同时给出1-3个合适的标签，用逗号分隔。"
                      "严格按照以下格式输出，不要添加其他内容："
                      "类型: [类型]\n标签: [标签1,标签2,标签3]"),
            ("human", "Issue标题：{title}\nIssue描述：{body}")
        ])
        self.classify_chain = self.classify_prompt | llm | StrOutputParser()
        
        # 常见问题知识库
        self.faq = {
            "安装失败": "请检查你的Python版本是否为3.10+，并运行 `pip install -r requirements.txt` 安装依赖。",
            "权限错误": "请确保你拥有仓库的读写权限，并且配置了正确的GitHub Token。",
            "Webhook不触发": "请检查Webhook的URL是否正确，以及防火墙是否开放了对应端口。",
            "启动失败": "请检查.env文件中的配置是否正确，特别是GITHUB_TOKEN和OPENAI_API_KEY。"
        }
    
    def process_issue(self, issue_number):
        """处理单个Issue"""
        try:
            issue = repo.get_issue(issue_number)
            if issue.state != "open" or issue.pull_request:
                return  # 跳过PR和已关闭的Issue
            
            # 1. 检查是否为常见问题
            for keyword, answer in self.faq.items():
                if keyword.lower() in issue.title.lower() or keyword.lower() in (issue.body or "").lower():
                    issue.create_comment(f"🤖 **自动回复**\n\n{answer}\n\n如果问题仍未解决，请补充更多细节。")
                    issue.add_to_labels("❓ 问题")
                    return
            
            # 2. AI分类和打标签
            classification = self.classify_chain.invoke({
                "title": issue.title,
                "body": issue.body or "无描述"
            })
            
            # 解析分类结果
            issue_type = "question"
            labels = []
            lines = classification.strip().split("\n")
            for line in lines:
                if line.startswith("类型:"):
                    issue_type = line.split(":", 1)[1].strip()
                elif line.startswith("标签:"):
                    labels = [label.strip() for label in line.split(":", 1)[1].strip().split(",") if label.strip()]
            
            # 映射类型到标签
            type_labels = {
                "bug": "🐛 Bug",
                "feature": "✨ 新功能",
                "question": "❓ 问题",
                "documentation": "📚 文档",
                "enhancement": "🚀 优化"
            }
            
            final_labels = [type_labels.get(issue_type, "❓ 问题")] + labels
            issue.add_to_labels(*final_labels)
            
            # 3. 自动分配负责人
            assignee = None
            if issue_type == "bug" and BUG_ASSIGNEE:
                assignee = BUG_ASSIGNEE
            elif issue_type == "documentation" and DOCS_ASSIGNEE:
                assignee = DOCS_ASSIGNEE
            
            if assignee:
                try:
                    issue.edit(assignees=[assignee])
                    issue.create_comment(f"🤖 已自动将此Issue分配给 @{assignee} 处理。")
                except GithubException:
                    print(f"无法分配给用户 {assignee}")
            
        except GithubException as e:
            print(f"处理Issue #{issue_number} 失败：{e}")
        except Exception as e:
            print(f"处理Issue #{issue_number} 发生未知错误：{e}")

class TechDebtAgent:
    """技术债监控Agent：每周扫描代码库，生成技术债报告"""
    
    def __init__(self):
        self.report_prompt = ChatPromptTemplate.from_messages([
            ("system", "你是一位技术架构师。请根据以下代码质量扫描结果，生成一份结构化的技术债报告。"
                      "包括：总体评估、高优先级问题、中优先级问题、低优先级问题、修复建议。"
                      "每个问题给出具体的文件和行号，以及修复建议。"),
            ("human", "代码规范问题：\n{pylint_result}\n\n安全漏洞：\n{bandit_result}")
        ])
        self.report_chain = self.report_prompt | llm | StrOutputParser()
    
    def generate_weekly_report(self):
        """生成每周技术债报告"""
        try:
            print("开始生成每周技术债报告...")
            temp_dir = clone_repo_to_temp(MAIN_BRANCH)
            
            # 运行代码检查
            pylint_output = subprocess.run(
                ["pylint", temp_dir, "--rcfile=config/pylintrc", "--output-format=text"],
                capture_output=True,
                text=True,
                timeout=120
            ).stdout
            
            bandit_output = subprocess.run(
                ["bandit", "-r", temp_dir, "-c", "config/bandit.yaml", "-f", "text"],
                capture_output=True,
                text=True,
                timeout=120
            ).stdout
            
            # 生成AI报告
            report = self.report_chain.invoke({
                "pylint_result": pylint_output,
                "bandit_result": bandit_output
            })
            
            # 创建Issue作为报告
            today = datetime.now().strftime("%Y-%m-%d")
            repo.create_issue(
                title=f"📊 每周技术债报告 - {today}",
                body=f"# 每周技术债报告\n\n{report}\n\n---\n*本报告由Git自动化运维Agent自动生成*",
                labels=["📊 技术债", "📅 周报"]
            )
            
            print(f"技术债报告生成完成: {today}")
            
        except Exception as e:
            print(f"生成技术债报告失败：{e}")
        finally:
            subprocess.run(["rm", "-rf", temp_dir], capture_output=True)

class ReleaseAgent:
    """版本发布Agent：自动生成更新日志+发布版本"""
    
    def __init__(self):
        self.changelog_prompt = ChatPromptTemplate.from_messages([
            ("system", "你是一位版本管理专家。请根据以下PR列表，生成一份清晰的更新日志。"
                      "按类别分组：新功能、Bug修复、文档更新、性能优化。"
                      "每个条目包含PR编号和标题，格式为：- #123 PR标题"),
            ("human", "上一个版本：{last_tag}\n本次版本：{new_tag}\n合并的PR：\n{pr_list}")
        ])
        self.changelog_chain = self.changelog_prompt | llm | StrOutputParser()
    
    def process_release(self, tag_name):
        """处理版本发布"""
        try:
            print(f"处理版本发布: {tag_name}")
            
            # 获取上一个标签
            tags = list(repo.get_tags())
            last_tag = tags[1].name if len(tags) > 1 else "v0.0.0"
            
            # 获取两个标签之间的PR
            compare = repo.compare(last_tag, tag_name)
            pr_list = [f"#{pr.number} {pr.title}" for pr in compare.pull_requests]
            
            if not pr_list:
                pr_list = ["无合并的PR"]
            
            # 生成更新日志
            changelog = self.changelog_chain.invoke({
                "last_tag": last_tag,
                "new_tag": tag_name,
                "pr_list": "\n".join(pr_list)
            })
            
            # 创建GitHub Release
            repo.create_git_release(
                tag=tag_name,
                name=f"Release {tag_name}",
                body=f"# 更新日志\n\n{changelog}\n\n---\n*本更新日志由Git自动化运维Agent自动生成*",
                draft=False,
                prerelease=False
            )
            
            print(f"版本发布完成: {tag_name}")
            
        except GithubException as e:
            print(f"处理版本发布失败：{e}")
        except Exception as e:
            print(f"处理版本发布发生未知错误：{e}")

# -------------------------- 主Agent调度器 --------------------------
class GitMasterAgent:
    def __init__(self):
        self.pr_agent = PRAuditAgent()
        self.issue_agent = IssueAgent()
        self.tech_debt_agent = TechDebtAgent()
        self.release_agent = ReleaseAgent()
    
    def handle_webhook_event(self, event_type, payload):
        """根据事件类型分发任务"""
        if event_type == "pull_request" and payload["action"] == "opened":
            pr_number = payload["pull_request"]["number"]
            print(f"收到新PR #{pr_number}，开始自动审核...")
            self.pr_agent.process_pr(pr_number)
        
        elif event_type == "issues" and payload["action"] == "opened":
            issue_number = payload["issue"]["number"]
            print(f"收到新Issue #{issue_number}，开始自动处理...")
            self.issue_agent.process_issue(issue_number)
        
        elif event_type == "create" and payload["ref_type"] == "tag":
            tag_name = payload["ref"]
            print(f"收到新标签 {tag_name}，开始自动发布...")
            self.release_agent.process_release(tag_name)

# 初始化主Agent
master_agent = GitMasterAgent()

# -------------------------- Webhook路由 --------------------------
@app.route("/webhook", methods=["POST"])
def github_webhook():
    if not verify_webhook_signature(request):
        return jsonify({"error": "无效的签名"}), 403
    
    event_type = request.headers.get("X-GitHub-Event")
    payload = request.get_json()
    
    master_agent.handle_webhook_event(event_type, payload)
    
    return jsonify({"status": "success"}), 200

@app.route("/health", methods=["GET"])
def health_check():
    """健康检查接口"""
    return jsonify({
        "status": "running",
        "time": datetime.now().isoformat(),
        "repo": REPO_NAME
    }), 200

# -------------------------- 定时任务 --------------------------
def setup_scheduler():
    """设置定时任务"""
    # 每周一上午9点生成技术债报告
    scheduler.add_job(
        master_agent.tech_debt_agent.generate_weekly_report,
        "cron",
        day_of_week="mon",
        hour=9,
        minute=0,
        id="weekly_tech_debt_report"
    )
    scheduler.start()

# -------------------------- 程序入口 --------------------------
if __name__ == "__main__":
    setup_scheduler()
    print("=" * 60)
    print("Git仓库自动化运维Agent已启动")
    print(f"Webhook地址：http://你的服务器IP:{PORT}/webhook")
    print(f"健康检查：http://你的服务器IP:{PORT}/health")
    print("=" * 60)
    app.run(host="0.0.0.0", port=PORT, debug=False)