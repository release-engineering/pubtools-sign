import logging

import pytest

from pubtools.sign.utils import set_log_level, sanitize_log_level, run_in_parallel, FData


def test_set_log_level():
    LOG = logging.getLogger()
    set_log_level(LOG, "DEBUG")
    assert LOG.level == logging.DEBUG
    set_log_level(LOG, "INFO")
    assert LOG.level == logging.INFO
    set_log_level(LOG, "WARNING")
    assert LOG.level == logging.WARNING
    set_log_level(LOG, "ERROR")
    assert LOG.level == logging.ERROR
    with pytest.raises(ValueError):
        set_log_level(LOG, "UNKNOWN")


def test_sanitize_log_level():
    assert sanitize_log_level("DEBUG") == "DEBUG"
    assert sanitize_log_level("INFO") == "INFO"
    assert sanitize_log_level("WARNING") == "WARNING"
    assert sanitize_log_level("Warning") == "WARNING"
    assert sanitize_log_level("ERROR") == "ERROR"
    assert sanitize_log_level("UNKNOWN") == "INFO"
    assert sanitize_log_level("unknown") == "INFO"
    assert sanitize_log_level("UnKnOwN") == "INFO"


def simulated_error(x: int) -> None:
    raise ValueError("Test")


def test_run_in_parallel_exception():
    with pytest.raises(ValueError):
        run_in_parallel(simulated_error, [FData([1])])
