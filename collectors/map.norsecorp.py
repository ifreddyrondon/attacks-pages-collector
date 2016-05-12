#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import json
import websocket
import ipwhois
from pprint import pprint


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


def on_error(ws, error):
    print error


def on_message(ws, message):
    base_url = "map.norsecorp.com"
    msg = json.loads(message)
    ip_address = msg['md5']
    attack_type = msg['type']
    host = get_host(ip_address)
    country = msg['country']
    who_is, _ = get_who_is_and_country(ip_address)

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

if __name__ == "__main__":
    ws = websocket.WebSocketApp("ws://mbsd.ipviking.com:443/")
    ws.on_error = on_error
    ws.on_message = on_message
    ws.run_forever()
