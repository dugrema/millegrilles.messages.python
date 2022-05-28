import datetime
import json


class DateFormatEncoder(json.JSONEncoder):
    """
    Permet de convertir les dates en format epoch automatiquement
    """

    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return int(obj.timestamp())

        # Let the base class default method raise the TypeError
        try:
            return json.JSONEncoder.default(self, obj)
        except TypeError:
            return str(obj)
