import os
from base64 import urlsafe_b64encode
from hashlib import sha3_384
from shutil import rmtree

from requests.models import Response
from requests.sessions import Session

salt = b'\xcb\x30\xc6\x98\x03\xeb\x3d\xac\x15\x4f\x2f\x4e\x77\x47\xbc\xe8\xe6\x41\x7f\x88\x69\xf2\xc3\x8d\x41\x8d\x63\xcc\xd2\x49\x29\x47\x9b\x02\x3b\xd1\x26\x8e\x44\xde\x12\x84\x2b\x1e\xd1\xd9\x3b\xaa\x12\xae\x7b\x33\x21\xfa\xf9\xca\xe5\xb2\xc9\x26\xf9\x09\x10\x18\x3f\x8c\xf4\x14\x55\x61\x65\x8c\x39\x0c\xe5\x7c\x9e\x0c\x5d\x75\xca\xf2\xb3\xc8\x15\x77\x88\x2e\x11\xed\xb0\x88\x5e\x6b\xa8\xe9\x34\xdb\x19\x37\x5b\x4b\x02\xe9\x29\xbf\x07\x0a\x3f\x84\x28\xc5\x5c\x29\x30\x00\x82\xc1\x4a\x97\x53\x67\xb9\x36\xe9\x7f\xae\x49\x18\xc6\x41\x06\x6c\xb9\x5a\xd1\x06\xd3\xc6\x26\x03\x89\xaf\x7f\x16\xde\x2c\x66\x01\x43\x95\x18\x5d\x18\x33\xb1\x69\x13\x97\xf9\xcd\x72\x74\xae\x89\xfe\x44\xbf\xdc\x77\x0f\x88\x8e\xbd\xd7\x4e\xaf\x7f\x08\x10\xbf\x9f\xe8\x2b\x24\xb4\x34\xc1\x43\xe5\x8c\x5e\xc3\x03\xe0\x2b\xf0\xc7\x84\xcc\x51\x7a\x07\xa3\xd0\x02\xb2\xab\xba\x84\x02\x2d\xb3\x01\xef\x1d\x4f\xec\x4b\x8e\xa7\x89\xa0\x24\xe7\x2c\x6f\x29\xa1\xb4\xb4\x0b\x54\x93\x0a\xb9\xb8\x70\xec\x37\xeb\x4d\xa1\xec\x8f\x4d\xce\x32\x85\xe0\xf3\x4e\xcf\x43\xab\x5b'


def versionstr(data: bytes) -> str:
    sha = sha3_384(data)
    sha.update(salt)
    for _ in range(64):
        sha.update(sha.digest())
        sha.update(salt)
    return urlsafe_b64encode(sha.digest()).decode()


def contain(base: str, other: str) -> bool:
    return other.endswith(base) and (
        len(other) == len(base) or
        other[-(len(base) + 1)] == '.'
    )


def sort_domains(domains: list, unblock_domains: list = []) -> list:
    def reverse(domain: str) -> list:
        return list(reversed(domain.split('.')))

    cur = list(map(lambda domain: (domain, reverse(domain)),
                   list(set(domains))))
    cur.sort(key=lambda tup: tup[1])

    if len(unblock_domains) == 0:
        return list(map(lambda tup: tup[0], cur))

    index = 0
    max_index = len(cur)
    result = []
    unblock_domains = sort_domains(unblock_domains)

    for dead_domain in unblock_domains:
        cur_domain = reverse(dead_domain)
        while index < max_index and cur_domain > cur[index][1]:
            result.append(cur[index][0])
            index += 1
        while index < max_index and contain(dead_domain, cur[index][0]):
            index += 1
        if index >= max_index:
            break

    if index < max_index:
        result.extend(map(lambda tup: tup[0], cur[index:]))

    return result


def adapt_ublock(domains: list) -> list:
    res = [domains[0]]
    size = len(domains)
    for i in range(1, size):
        if not contain(res[-1], domains[i]):
            res.append(domains[i])
    return res


header_text = """
! Title: filter-4400e6cd / external
! Expires: 2 days
! Homepage: https://github.com/PetrichorA/filter-4400e6cd
! Description: 自用屏蔽规则（此规则适用于浏览器）
! Subscribe: https://filter-4400e6cd.pages.dev/external.txt
! Subscribe (jsDelivr): https://cdn.jsdelivr.net/gh/PetrichorA/filter-4400e6cd@main/external.txt
! Subscribe (Raw): https://raw.githubusercontent.com/PetrichorA/filter-4400e6cd/main/external.txt
! Version: {version}
""".strip()

working_directory = os.path.normpath(os.path.join(os.path.dirname(
    os.path.abspath(__file__)), '..', '..', 'external'))


session = Session()


def get(url: str) -> Response:
    while True:
        try:
            resp = session.get(url, timeout=3.0)
            if content_length := resp.headers.get('content-length'):
                assert str(len(resp.content)) == content_length
            return resp
        except Exception as err:
            print('error', err)


def transform_hosts(rules: str) -> str:
    return '\n'.join(map(
        lambda domain: f'||{domain}^',
        adapt_ublock(sort_domains(rules.splitlines()))))


def transform_strip_comments(rules: str) -> str:
    return '\n'.join(filter(lambda line: line and not line.startswith('!') and not line.startswith('['), rules.splitlines()))


trusted_3p = (
    ('https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0',
     transform_hosts),
    ('https://github.com/uBlockOrigin/uAssets/raw/master/filters/annoyances.txt',
     transform_strip_comments),
    ('https://secure.fanboy.co.nz/fanboy-cookiemonster.txt',
     transform_strip_comments),
    ('https://secure.fanboy.co.nz/fanboy-annoyance.txt',
     transform_strip_comments),
)

if __name__ == '__main__':
    content = []

    for name in os.listdir(working_directory):
        if name.endswith('.txt'):
            name = os.path.join(working_directory, name)
            with open(name, 'rb') as fin:
                namestr = versionstr(fin.read()) + '.txt'
            ename = os.path.join(working_directory, namestr)
            if name != ename:
                os.rename(name, ename)
            content.append(namestr)

    urls_dir = os.path.join(working_directory, 'url')
    rmtree(path=urls_dir, ignore_errors=True)
    os.mkdir(urls_dir)

    for url, transformer in trusted_3p:
        name = versionstr(url.encode()) + '.txt'
        with open(os.path.join(urls_dir, name), 'w', encoding='utf-8') as fout:
            fout.write(transformer(get(url).text.strip()))
        content.append(f'url/{name}')

    content.sort()
    content = '\n'.join(
        map(lambda namestr: '!#include {}/{}'.format(working_directory, namestr), content))
    version = versionstr(content.encode())

    with open('external.txt', 'w', encoding='utf-8') as fout:
        fout.write(header_text.format(version=version))
        fout.write('\n\n')
        fout.write(content)
