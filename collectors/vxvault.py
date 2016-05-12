#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import re
import bz2
import requests
import ipwhois
from pprint import pprint


def get_url(url):
    try:
        res = requests.get(url)
    except requests.exceptions.ConnectionError:
        raise requests.exceptions.ConnectionError("DNS lookup failures")
    else:
        if res.status_code != 200:
            raise requests.exceptions.ConnectionError(
                "the {}, answer with {} error".format(url, res.status_code))

        return res


def get_ip(name):
    attempts = 5
    ip = "undefined"
    while attempts:
        try:
            data = socket.gethostbyname_ex(name)
            ip = data[2][0]
            break
        except (socket.herror, socket.gaierror):
            attempts -= 1

    return ip


def get_who_is_and_country(ip):
    try:
        ip_obj = ipwhois.IPWhois(ip)
        who_is = ip_obj.lookup(retry_count=5)
        return str(who_is), who_is['asn_country_code']
    except ipwhois.exceptions.IPDefinedError:
        return "Private-Use Networks", "undefined"
    except ipwhois.exceptions.WhoisLookupError:
        return "undefined", "undefined"


def gather():
    url_regex = '(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
    base_url = "http://vxvault.net//URL_List.php"
    attack_type = "undefined"
    res = get_url(base_url)

    for line in res.iter_lines():
        if line == "":
            continue

        site_url = line
        m = re.search(url_regex, site_url)

        if not m or line[:4] != "http":
            continue

        host = m.group('host')
        ip_address = get_ip(host)
        if ip_address == "undefined":
            who_is, country = "undefined", "undefined"
        else:
            who_is, country = get_who_is_and_country(ip_address)

        doc = {
            'IP': ip_address,
            'SourceInfo': base_url,
            'Type': attack_type,
            'Country': country,
            'Domain': host,
            'URL': site_url,
            'WhoIsInfo': who_is,
        }

        pprint(doc)

if __name__ == '__main__':
    gather()
