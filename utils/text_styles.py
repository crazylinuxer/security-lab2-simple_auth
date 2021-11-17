__all__ = ['green', 'red', 'yellow', 'blue', 'cyan', 'magenta', 'grey', 'bold', 'underline']


def _add_control_sequence(seq: str, inp: str) -> str:
    result = seq + inp
    if not result.endswith("\033[0m"):
        result += "\033[0m"
    return result


def grey(inp: str) -> str:
    """Returns string in grey color to print"""
    return _add_control_sequence("\033[90m", inp)


def red(inp: str) -> str:
    """Returns string in red color to print"""
    return _add_control_sequence("\033[91m", inp)


def green(inp: str) -> str:
    """Returns string in green color to print"""
    return _add_control_sequence("\033[92m", inp)


def yellow(inp: str) -> str:
    """Returns string in yellow color to print"""
    return _add_control_sequence("\033[93m", inp)


def blue(inp: str) -> str:
    """Returns string in blue color to print"""
    return _add_control_sequence("\033[94m", inp)


def magenta(inp: str) -> str:
    """Returns string in magenta color to print"""
    return _add_control_sequence("\033[95m", inp)


def cyan(inp: str) -> str:
    """Returns string in cyan color to print"""
    return _add_control_sequence("\033[36m", inp)


def bold(inp: str) -> str:
    """Returns bold string to print"""
    return _add_control_sequence("\033[1m", inp)


def underline(inp: str) -> str:
    """Returns underlined string to print"""
    return _add_control_sequence("\033[4m", inp)


def blinking(inp: str) -> str:
    """Returns blinking string to print"""
    return _add_control_sequence("\033[5m", inp)
