import datetime
import subprocess
import os

from .conf.conf import CONFIG_PATHS


def set_log_level(logger, level):
    """Set log level for provided logger.

    :param logger: logger
    :type logger: logging.Logger
    :param level: logging level
    :type level: str
    """
    if level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        raise ValueError(f"Unknown log level {level}")
    logger.setLevel(level.upper())


def isodate_now():
    """Return current datetime in ISO-8601.

    :return: str
    """
    return datetime.datetime.utcnow().isoformat() + "Z"


def run_command(cmd, env=None):
    """Run external command and return Process instance."""
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env
    )
    return process


def _get_config_file(config_candidate):
    if not os.path.exists(config_candidate):
        for config_candidate in CONFIG_PATHS:
            if os.path.exists(os.path.expanduser(config_candidate)):
                break
        else:
            raise ValueError(
                "No configuration file found: %s" % list(set(CONFIG_PATHS + [config_candidate]))
            )
    return config_candidate
