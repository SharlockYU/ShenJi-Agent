"""
知识库模块 - RAG 检索增强生成
"""

from typing import List, Optional
from langchain_community.vectorstores import Chroma
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter


class KnowledgeBase:
    """知识库管理类"""
    
    def __init__(self, persist_directory: str = "./knowledge_base/vector_store"):
        self.embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200
        )
        self.vector_store = Chroma(
            persist_directory=persist_directory,
            embedding_function=self.embeddings.embed_documents
        )
    
    def add_documents(self, documents: List[str]) -> None:
        """添加文档到向量存储"""
        self.vector_store.add_documents(documents=documents)
    
    def search(self, query: str, k: int = 5) -> List[str]:
        """搜索相关文档"""
        results = self.vector_store.similarity_search(
            query,
            k=k
        )
        return [doc.page_content for doc in results]
    
    def update(self) -> None:
        """更新知识库"""
        # TODO: 实现从 Git 拉取最新内容
