import json
import pytz


def liste_timezones():
    with open('/tmp/python_timezones.json', 'w') as fichier:
        json.dump(pytz.all_timezones, fichier)


if __name__ == '__main__':
    liste_timezones()
