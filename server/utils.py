# server/utils.py

import sys
import os

# 获取当前脚本的绝对路径
current_dir = os.path.dirname(os.path.abspath(__file__))

# 获取项目根目录（假设 server/ 和 common/ 是同级的）
project_root = os.path.abspath(os.path.join(current_dir, os.pardir))

# 将项目根目录添加到系统路径中
sys.path.append(project_root)

from common.utils import load_or_generate_keys, generate_fingerprint

# 服务器特有的工具函数可以在这里添加
