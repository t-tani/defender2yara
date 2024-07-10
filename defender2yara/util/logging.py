import logging
from colorama import Fore, Style, init
from tqdm import tqdm


class TqdmLoggingHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__()

    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.write(msg)
            self.flush()
        except Exception:
            self.handleError(record)

class ColorFormatter(logging.Formatter):
    # 初期化
    def __init__(self, fmt, datefmt):
        super().__init__(fmt, datefmt)
        self.FORMATS = {
            logging.DEBUG: self._color_format(Fore.BLUE, fmt),
            logging.INFO: self._color_format(Fore.GREEN, fmt),
            logging.WARNING: self._color_format(Fore.YELLOW, fmt),
            logging.ERROR: self._color_format(Fore.RED, fmt),
            logging.CRITICAL: self._color_format(Fore.RED + Style.BRIGHT, fmt),
        }
        self.datefmt = datefmt

    def _color_format(self, color, fmt):
        return Fore.LIGHTWHITE_EX + '[%(asctime)s]' + Style.RESET_ALL + f' {color}[%(levelname)s]' + Style.RESET_ALL + ' %(message)s'

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, self.datefmt)
        return formatter.format(record)

def setup_logger(name, debug=False):
    if debug:
        level = logging.DEBUG
    else:
        level = logging.INFO
    
    init()  # colorama
    fmt = '[%(asctime)s] [%(levelname)s] %(message)s'
    datefmt = '%Y-%m-%d %H:%M:%S'

    logger = logging.getLogger(name)
    logger.setLevel(level)
    

    console_handler = TqdmLoggingHandler()
    console_handler.setFormatter(ColorFormatter(fmt, datefmt))

    # formatter = logging.Formatter(
    #     fmt='[%(asctime)s] [%(levelname)s] %(message)s',
    #     datefmt='%Y-%m-%d %H:%M:%S'
    # )
    # console_handler.setFormatter(formatter)

    if not logger.hasHandlers():
        logger.addHandler(console_handler)
    
    return logger

def suppress_logging(name):
    logging.getLogger(name).setLevel(logging.CRITICAL)