import requests

API_ENDPOINT = 'https://api.ip2location.io/'


def resolve_ip(API_KEY, ip):
    try:
        r = requests.get(API_ENDPOINT, params={
            'key': API_KEY,
            'format': 'json',
            'ip': ip
        })
        if r.status_code == requests.codes.ok:
            return r.json()
        else:
            return None
    except Exception as e:
        return None
