#ui.py
import logging
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Define custom log levels
TRACE_LEVEL_NUM = 5  # New level below DEBUG
SYSTEM_LEVEL_NUM = 25  # Existing custom level
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")
logging.addLevelName(SYSTEM_LEVEL_NUM, "SYSTEM")

# Extend Logger class to add trace and system methods
def trace(self, message, *args, **kwargs):
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kwargs)

def system(self, message, *args, **kwargs):
    if self.isEnabledFor(SYSTEM_LEVEL_NUM):
        self._log(SYSTEM_LEVEL_NUM, message, args, **kwargs)

logging.Logger.trace = trace
logging.Logger.system = system

# Define the color
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'TRACE': Fore.LIGHTCYAN_EX,
        'DEBUG': Fore.LIGHTYELLOW_EX,
        'INFO': Fore.LIGHTGREEN_EX,
        'SYSTEM': Fore.LIGHTBLUE_EX,
        'WARNING': '\033[38;5;214m',
        'ERROR': Fore.LIGHTRED_EX,
        'CRITICAL': Fore.LIGHTMAGENTA_EX,
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

# Set the log level dynamically
def set_log_level(logger, level_name):
    # Convert level name to upper case and get the corresponding level
    level = logging.getLevelName(level_name.upper())
    if isinstance(level, int):  # Check if the level is valid
        logger.setLevel(level)
    else:
        logger.setLevel(logging.INFO)  # Default to INFO if the level is not found

# Test script for ui.py only, not included in the main program
if __name__ == "__main__":
    logger = init_logger()
    
    # Set the level to DEBUG
    set_log_level(logger, 'TRACE')

    logger.trace("This is a trace message, for debugging a stable feature (usually not activated).")
    logger.debug("This is a debug message, for debugging a feature (should be actived only in debug mode).")
    logger.info("This is an information message, for general information.")
    logger.system("This is a system message, for system information.")
    logger.warning("This is a warning message, for warning information.")
    logger.error("This is an error message, for error information")
    logger.critical("This is a critical message, for critical information.")
