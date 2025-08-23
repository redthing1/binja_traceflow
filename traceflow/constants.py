PLUGIN_KEY = "traceflow"
PLUGIN_NAME = "TraceFlow"

# UI constants
TRACE_VIEW_WINDOW_SIZE = 10  # number of entries to show before/after current position


def get_supported_extensions() -> list[str]:
    """get list of file extensions supported by all parsers"""
    from .parsers import get_all_parsers

    extensions = set()
    for parser_class in get_all_parsers():
        extensions.update(parser_class.get_file_extensions())

    return sorted(extensions)


def get_file_dialog_filter() -> str:
    """get file dialog filter string for supported trace formats"""
    extensions = get_supported_extensions()
    filters = []

    # add individual extension filters
    for ext in extensions:
        filters.append(f"*.{ext}")

    # add "all files" fallback
    filters.append("*")

    return ";;".join(filters)
