from concurrent import futures
from concurrent.futures.thread import ThreadPoolExecutor
from dataclasses import dataclass, field
import datetime
import subprocess
import os
import logging
import time
from typing import Any, Dict, List, Union, Callable, cast, Iterable, Tuple

from .conf.conf import CONFIG_PATHS

from pubtools.tracing import get_trace_wrapper

tw = get_trace_wrapper()
LOG = logging.getLogger("pubtools.sign.utils")


def set_log_level(logger: logging.Logger, level: str) -> None:
    """Set log level for provided logger.

    :param logger: logger
    :type logger: logging.Logger
    :param level: logging level
    :type level: str
    """
    if level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        raise ValueError(f"Unknown log level {level}")
    logger.setLevel(level.upper())


def sanitize_log_level(log_level: str) -> str:
    """Sanitize log level. Returns INFO if provided value is invalid.

    Args:
        log_level (str): log level
    Returns:
        str: log level
    """
    if log_level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        return "INFO"
    else:
        return log_level.upper()


def isodate_now() -> str:
    """Return current datetime in ISO-8601.

    :return: str
    """
    return datetime.datetime.utcnow().isoformat() + "Z"


@tw.instrument_func(args_to_attr=True)
def run_command(
    cmd: List[str], env: Union[Dict[str, Any], None] = None, tries: int = 3
) -> Tuple[str, str, int]:
    """Run external command and return stdout, stderr and returncode."""

    def _run_command(
        cmd: List[str], env: Union[Dict[str, Any], None] = None
    ) -> Tuple[str, str, int]:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env
        )
        stdout, stderr = process.communicate()
        return (stdout, stderr, process.returncode)

    for i in range(tries):
        stdout, stderr, returncode = _run_command(cmd, env)
        if returncode != 0:
            wait_time = i * 10
            LOG.warning(
                "Run command failed. Will retry in %d seconds [try %s/%s]: %s"
                % (wait_time, i + 1, tries, stderr)
            )
            time.sleep(wait_time)
            stdout, stderr, returncode = _run_command(cmd, env)
        else:
            break
    return (stdout, stderr, returncode)


def _get_config_file(config_candidate: str) -> str:
    if not os.path.exists(config_candidate):
        for config_candidate in CONFIG_PATHS:
            if os.path.exists(os.path.expanduser(config_candidate)):
                break
        else:
            raise ValueError(
                "No configuration file found: %s" % list(set(CONFIG_PATHS + [config_candidate]))
            )
    return config_candidate


@dataclass
class FData:
    """Dataclass for holding data for a function execution.

    Args:
        args (Iterable[Any]): Arguments for the function.
        kwargs (Dict[str, Any]): Keyword arguments for the function.
    """

    args: Iterable[Any]
    kwargs: Dict[str, Any] = field(default_factory=dict)


def run_in_parallel(
    func: Callable[..., Any], data: Iterable[FData], threads: int = 10
) -> Dict[Any, Any]:
    """Run method on data in parallel.

    Args:
        func (function): Function to run on data
        data (list): List of tuples which are used as arguments for the function
    Returns:
        dict: List of result in the same order as data.
    """
    future_results = {}
    results = {}
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_results = {
            executor.submit(func, *data_entry.args, **data_entry.kwargs): n
            for n, data_entry in enumerate(data)
        }
        for future in futures.as_completed(future_results):
            if future.exception() is not None:
                raise cast(BaseException, future.exception())
            results[future_results[future]] = future.result()
    return dict(sorted(results.items(), key=lambda kv: kv[0]))
