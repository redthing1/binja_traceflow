from .constants import PLUGIN_KEY, PLUGIN_NAME

_LOGGER = None


def get_logger(bv):
    global _LOGGER
    if _LOGGER is None:
        _LOGGER = bv.create_logger(PLUGIN_NAME)
    return _LOGGER


def log_info(bv, message):
    logger = get_logger(bv)
    logger.log_info(message)


def log_error(bv, message):
    logger = get_logger(bv)
    logger.log_error(message)


def log_warn(bv, message):
    logger = get_logger(bv)
    logger.log_warn(message)


def log_debug(bv, message):
    logger = get_logger(bv)
    logger.log_debug(message)
