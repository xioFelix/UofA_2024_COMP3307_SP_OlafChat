import logging
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Added a self-defined log level "system" at level 25
SYSTEM_LEVEL_NUM = 25
logging.addLevelName(SYSTEM_LEVEL_NUM, "SYSTEM")

# Extend the Logger class with a new method "system"
def system(self, message, *args, **kwargs):
    if self.isEnabledFor(SYSTEM_LEVEL_NUM):
        self._log(SYSTEM_LEVEL_NUM, message, args, **kwargs)

logging.Logger.system = system

# Define the color
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
        # Get the color of the log level
        log_color = self.COLORS.get(record.levelname, Fore.WHITE)
        
        # Set the alignment of the log level to 8 characters
        levelname = f"{log_color}{record.levelname:<8}"
        
        # Add color for "|" symbol
        log_message = f"{log_color}|{levelname}|{Style.RESET_ALL}  {record.msg}"

        # Update the message
        record.msg = log_message

        return super().format(record)

# Intialize the logger
def init_logger(name='app', level=logging.INFO):
    # Initalize the logger
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Check if the logger has been configured
    if not logger.handlers:
        # Create a console handler and set the format
        console_handler = logging.StreamHandler()
        formatter = ColoredFormatter('%(message)s')  # Adjust the format of the log message
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger

# Set the log level diamiclly
def set_log_level(logger, level_name):
    level = getattr(logging, level_name.upper(), logging.INFO)
    logger.setLevel(level)

# Test script for ui.py only
if __name__ == "__main__":
    logger = init_logger()
    
    # Set the level to DEBUG
    set_log_level(logger, 'DEBUG')

    logger.debug("这是调试信息")
    logger.info("这是一般信息")
    logger.system("这是系统级信息")
    logger.warning("这是警告信息")
    logger.error("这是错误信息")
    logger.critical("这是严重错误信息")
