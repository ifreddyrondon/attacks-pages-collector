#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import re
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


def get_host(ip):
    attempts = 5
    host = "undefined"
    while attempts:
        try:
            data = socket.gethostbyaddr(ip)
            host = data[0]
            break
        except socket.herror:
            attempts -= 1

    return host


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
    base_url = "http://www.nothink.org/blacklist/blacklist_malware_http.txt"
    attack_type = "Malware IPs"

    res = get_url(base_url)
    for line in res.iter_lines():
        ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
        if len(ip) == 0:
            continue

        ip_address = ip[0]
        host = get_host(ip_address)
        who_is, country = get_who_is_and_country(ip_address)

        doc = {
            'IP': ip_address,
            'SourceInfo': base_url,
            'Type': attack_type,
            'Country': country,
            'Domain': host,
            'URL': host,
            'WhoIsInfo': who_is,
        }

        pprint(doc)

if __name__ == '__main__':
    gather()
