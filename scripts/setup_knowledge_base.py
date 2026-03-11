#!/usr/bin/env python3
"""
初始化知识库 - 下载并设置 PayloadsAllTheThings 知识库
"""

import os
import sys
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from agent.knowledge import KnowledgeBase


def clone_payloads_all_the_things():
    """克隆 PayloadsAllTheThings 仓库"""
    payloads_dir = project_root / "knowledge_base" / "PayloadsAllTheThings"
    
    if payloads_dir.exists():
        print(f"[✓] PayloadsAllTheThings 已存在于 {payloads_dir}")
        return payloads_dir
    
    print("[*] 正在克隆 PayloadsAllTheThings...")
    
    import subprocess
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", 
             "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
             str(payloads_dir)],
            check=True
        )
        print(f"[✓] 克隆完成: {payloads_dir}")
        return payloads_dir
    except subprocess.CalledProcessError as e:
        print(f"[✗] 克隆失败: {e}")
        return None
    except FileNotFoundError:
        print("[✗] Git 未安装，请先安装 Git")
        return None


def load_documents_from_payloads(payloads_dir: Path):
    """从 PayloadsAllTheThings 加载文档"""
    documents = []
    
    # 遍历所有 markdown 文件
    for md_file in payloads_dir.rglob("*.md"):
        try:
            content = md_file.read_text(encoding="utf-8")
            if content and len(content) > 100:  # 忽略过小的文件
                documents.append(content)
        except Exception as e:
            print(f"[!] 跳过文件 {md_file}: {e}")
    
    return documents


def main():
    print("=" * 60)
    print("  PentestAgent 知识库初始化脚本")
    print("=" * 60)
    print()
    
    # 1. 克隆知识库
    payloads_dir = clone_payloads_all_the_things()
    if not payloads_dir:
        print("[✗] 初始化失败")
        sys.exit(1)
    
    # 2. 加载文档
    print("\n[*] 正在加载文档...")
    documents = load_documents_from_payloads(payloads_dir)
    print(f"[✓] 加载了 {len(documents)} 个文档")
    
    if not documents:
        print("[!] 没有找到文档")
        sys.exit(0)
    
    # 3. 初始化知识库
    print("\n[*] 正在初始化向量存储...")
    try:
        kb = KnowledgeBase(
            persist_directory=str(project_root / "knowledge_base" / "vector_store")
        )
        
        # 分批添加文档（避免内存问题）
        batch_size = 50
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]
            kb.add_documents(batch)
            print(f"  [{i+1}-{min(i+batch_size, len(documents))}/{len(documents)}]")
        
        print(f"\n[✓] 知识库初始化完成!")
        print(f"[i] 向量存储位置: {project_root / 'knowledge_base' / 'vector_store'}")
        
    except Exception as e:
        print(f"[✗] 初始化失败: {e}")
        print("\n[!] 请确保已配置 OPENAI_API_KEY 环境变量")
        sys.exit(1)
    
    # 4. 测试搜索
    print("\n[*] 测试搜索功能...")
    try:
        results = kb.search("SQL injection", k=3)
        print(f"[✓] 搜索测试成功，返回 {len(results)} 个结果")
    except Exception as e:
        print(f"[!] 搜索测试失败: {e}")


if __name__ == "__main__":
    main()
