import logging
from colorama import Fore, Style, init

# 初始化 colorama
init(autoreset=True)

# 自定义一个新的日志级别 SYSTEM，选择数值 25（介于 INFO 和 WARNING 之间）
SYSTEM_LEVEL_NUM = 25
logging.addLevelName(SYSTEM_LEVEL_NUM, "SYSTEM")

# 扩展 Logger 类，添加 system 方法
def system(self, message, *args, **kwargs):
    if self.isEnabledFor(SYSTEM_LEVEL_NUM):
        self._log(SYSTEM_LEVEL_NUM, message, args, **kwargs)

logging.Logger.system = system

# 定义带颜色的日志格式化类
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': Fore.YELLOW,
        'INFO': Fore.LIGHTGREEN_EX,
        'SYSTEM': Fore.LIGHTBLUE_EX,
        'WARNING': Fore.LIGHTYELLOW_EX,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA,
    }

    def format(self, record):
        # 获取日志级别的颜色
        log_color = self.COLORS.get(record.levelname, Fore.WHITE)
        
        # 设置日志级别的宽度为 8 并加颜色
        levelname = f"{log_color}{record.levelname:<8}"
        
        # 为两侧的分隔符添加颜色，并在末尾添加 Style.RESET_ALL
        log_message = f"{log_color}|{levelname}|{Style.RESET_ALL}  {record.msg}"

        # 更新记录中的消息
        record.msg = log_message

        return super().format(record)

# 初始化日志记录器
def init_logger(name='app', level=logging.INFO):
    # 创建日志记录器
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # 检查是否已添加了处理器，防止重复添加
    if not logger.handlers:
        # 创建控制台处理器并设置格式
        console_handler = logging.StreamHandler()
        formatter = ColoredFormatter('%(message)s')  # 调整格式化字符串，只输出消息
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger

# 动态调整日志级别
def set_log_level(logger, level_name):
    level = getattr(logging, level_name.upper(), logging.INFO)
    logger.setLevel(level)

# 在 ui.py 内测试日志配置
if __name__ == "__main__":
    logger = init_logger()
    
    # 调整日志级别为 DEBUG
    set_log_level(logger, 'DEBUG')

    logger.debug("这是调试信息")
    logger.info("这是一般信息")
    logger.system("这是系统级信息")  # 使用自定义的 SYSTEM 日志级别
    logger.warning("这是警告信息")
    logger.error("这是错误信息")
    logger.critical("这是严重错误信息")
