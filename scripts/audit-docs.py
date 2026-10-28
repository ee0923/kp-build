#!/usr/bin/env python3
"""Reject automatic external resources in the generated static help documents."""
from html.parser import HTMLParser
from pathlib import Path
import re
import sys

REMOTE = re.compile(r'^(?:https?:)?//', re.I)


def css_requests(css):
    css = re.sub(r'/\*.*?\*/', '', css, flags=re.S)
    return re.findall(r'(?:@import\s+|url\(\s*)[\'\"]?(?:https?:)?//[^\s\'\";)]+', css, re.I)


class Resources(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.errors = []
        self.in_style = False

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == 'script':
            self.errors.append('script in static help')
        if tag == 'style':
            self.in_style = True
        keys = ['src', 'poster', 'data']
        if tag in ('link', 'base'):
            keys.append('href')
        for key in keys:
            value = (attrs.get(key) or '').strip()
            if REMOTE.match(value):
                self.errors.append(f'{tag}.{key}: {value}')
        if re.search(r'(?:https?:)?//', attrs.get('srcset') or '', re.I):
            self.errors.append('external srcset')
        if tag == 'meta' and (attrs.get('http-equiv') or '').lower() == 'refresh':
            self.errors.append('automatic refresh')
        self.errors.extend(css_requests(attrs.get('style') or ''))

    def handle_endtag(self, tag):
        if tag == 'style':
            self.in_style = False

    def handle_data(self, data):
        if self.in_style:
            self.errors.extend(css_requests(data))


def violations(html):
    parser = Resources()
    parser.feed(html)
    parser.close()
    return parser.errors


def main(folder):
    for name in ('GettingStarted', 'UserGuide', 'KeyboardShortcuts'):
        path = Path(folder) / f'KeePassXC_{name}.html'
        errors = violations(path.read_text())
        if errors:
            raise ValueError(f'{path.name}: {errors}')
    print('PASS: all three generated help documents have no automatic external resources')


if __name__ == '__main__':
    main(sys.argv[1])
