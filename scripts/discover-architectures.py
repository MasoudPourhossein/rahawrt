#!/usr/bin/env python3
"""Extract official package architecture directories; discovery is not support."""
import argparse
import datetime as dt
from html.parser import HTMLParser
import json
import re
import urllib.parse
import urllib.request


class Directories(HTMLParser):
    def __init__(self):
        super().__init__()
        self.architectures = set()

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            href = dict(attrs).get('href', '')
            if re.fullmatch(r'[a-z0-9][a-z0-9_-]+/', href):
                self.architectures.add(href[:-1])


def extract(html):
    parser = Directories()
    parser.feed(html)
    if not parser.architectures:
        raise ValueError('official index contains no architecture directories')
    return sorted(parser.architectures)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('release')
    args = p.parse_args()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', args.release):
        p.error('exact OpenWrt release required')
    source = 'https://downloads.openwrt.org/releases/'+args.release+'/packages/'
    with urllib.request.urlopen(source, timeout=30) as response:
        if urllib.parse.urlparse(response.url).hostname != 'downloads.openwrt.org':
            raise ValueError('unexpected official index redirect')
        architectures = extract(response.read(2**20).decode('utf-8'))
    print(json.dumps(dict(release=args.release, source=source, retrieved_at=dt.datetime.now(dt.timezone.utc).isoformat(), architectures=architectures, state='discovered_only'), indent=2))


if __name__ == '__main__':
    main()
