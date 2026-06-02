import os
import torch
from .core import AIClient
# 忽略警告
import warnings
warnings.filterwarnings("ignore")

__version__ = "4.0.0"
__all__ = ['AIClient', 'model']  # 允许外部访问加载的模型

# 获取模型文件路径
model_path = os.path.join(os.path.dirname(__file__), "model.pt")

# 加载模型
try:
    model = torch.load(model_path, map_location='cpu', weights_only=False)
except Exception as e:
    pass
# 可选：将模型附加到模块中，供 SDK 用户访问
