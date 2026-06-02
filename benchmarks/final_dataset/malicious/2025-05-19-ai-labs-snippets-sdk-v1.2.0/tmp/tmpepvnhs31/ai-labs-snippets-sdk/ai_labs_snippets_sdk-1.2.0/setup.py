from setuptools import setup, find_packages

setup(
    name="ai-labs-snippets-sdk",
    version="1.2.0",
    description="AI Labs Snippets SDK for Python",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="ai-labs",
    author_email="ai-labs@alilaba-inc.com",
    url="https://github.com/aliyun-ai-labs/ai-labs-snippets",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "torch==2.6.0",  # 明确指定 PyTorch 版本
    ],
    package_data={
        "ai_labs_snippets_sdk": ["model.pt"],  # 包含模型文件
    },
    include_package_data=True,  # 确保包含非代码文件
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
