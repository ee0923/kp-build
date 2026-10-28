"""Choose application, runner and target architecture for the single build workflow."""
import json
import sys

TARGETS = [
    {'id': 'android', 'name': 'KeePass2Android', 'app': 'keepass2android', 'platform': 'android',
     'arch': 'armv7-arm64-x86-x64', 'runner': 'ubuntu-24.04', 'timeout': 180,
     'secret': 'KEEPASS2ANDROID_CUSTOMIZE_SCRIPT'},
    {'id': 'linux', 'name': 'KeePassXC Linux', 'app': 'keepassxc', 'platform': 'linux',
     'arch': 'x64', 'runner': 'ubuntu-24.04', 'timeout': 360,
     'secret': 'KEEPASSXC_CUSTOMIZE_SCRIPT'},
    {'id': 'macos', 'name': 'KeePassXC macOS', 'app': 'keepassxc', 'platform': 'macos',
     'arch': 'arm64', 'runner': 'macos-15', 'timeout': 360,
     'secret': 'KEEPASSXC_CUSTOMIZE_SCRIPT'},
    {'id': 'windows', 'name': 'KeePassXC Windows', 'app': 'keepassxc', 'platform': 'windows',
     'arch': 'x64', 'runner': 'windows-2022', 'timeout': 360,
     'secret': 'KEEPASSXC_CUSTOMIZE_SCRIPT'},
]


def select(target):
    if target not in {'all', 'desktop', *(item['id'] for item in TARGETS)}:
        raise ValueError('Unknown build target')
    return {'include': [item for item in TARGETS if target == 'all' or item['id'] == target
                        or (target == 'desktop' and item['app'] == 'keepassxc')]}


if __name__ == '__main__':
    print('matrix=' + json.dumps(select(sys.argv[1]), separators=(',', ':')))
