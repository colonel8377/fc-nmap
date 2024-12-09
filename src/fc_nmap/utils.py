import signal
import functools
import logging

# Logging setup
logger = logging.getLogger(__name__)

class TimeoutError(Exception):
    """Custom timeout exception for the decorator."""
    pass

def timeout_decorator(seconds=10, error_message="Function call timed out"):
    """Decorator to enforce a timeout on a function."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            def handler(signum, frame):
                raise TimeoutError(error_message)

            # Set the signal handler and the alarm
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(seconds)

            try:
                result = func(*args, **kwargs)
            finally:
                # Disable the alarm after the function completes
                signal.alarm(0)

            return result

        return wrapper

    return decorator