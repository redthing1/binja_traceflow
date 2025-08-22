import json

from binaryninja.settings import Settings

from .constants import PLUGIN_KEY, PLUGIN_NAME

my_settings = Settings()
my_settings.register_group(PLUGIN_KEY, PLUGIN_NAME)
