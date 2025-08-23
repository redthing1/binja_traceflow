import json

from binaryninja.settings import Settings

from .constants import PLUGIN_KEY, PLUGIN_NAME

my_settings = Settings()
my_settings.register_group(PLUGIN_KEY, PLUGIN_NAME)

# register frontier highlighting settings
my_settings.register_setting(
    f"{PLUGIN_KEY}.frontierSize",
    json.dumps({
        "title": "Frontier Size",
        "description": "Number of past/future instructions to highlight around current position",
        "type": "number",
        "default": 8,
        "minValue": 1,
        "maxValue": 32
    })
)
