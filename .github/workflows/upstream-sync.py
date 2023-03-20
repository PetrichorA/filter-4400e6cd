import os
from shutil import rmtree

from adapt_ublock import adapt_ublock
from requests.models import Response
from requests.sessions import Session
from sort_domains import sort_domains
from versionstr import versionstr

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

wd = 'external'
content = []

for name in os.listdir(wd):
    if name.endswith('.txt'):
        name = os.path.join(wd, name)
        with open(name, 'rb') as fin:
            namestr = versionstr(fin.read()) + '.txt'
        ename = os.path.join(wd, namestr)
        if name != ename:
            os.rename(name, ename)
        content.append(namestr)


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


def transformer_hosts(rules: str) -> str:
    return '\n'.join(map(
        lambda domain: f'||{domain}^',
        adapt_ublock(sort_domains(rules.splitlines()))))


def transformer_strip_comments(rules: str) -> str:
    return '\n'.join(filter(lambda line: line and not line.startswith('!') and not line.startswith('['), rules.splitlines()))


trusted_3p = (
    ('https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0',
     transformer_hosts),
    ('https://github.com/uBlockOrigin/uAssets/raw/master/filters/annoyances.txt',
     transformer_strip_comments),
    ('https://secure.fanboy.co.nz/fanboy-cookiemonster.txt',
     transformer_strip_comments),
    ('https://secure.fanboy.co.nz/fanboy-annoyance.txt',
     transformer_strip_comments),
)

urls_dir = os.path.join(wd, 'url')
rmtree(path=urls_dir, ignore_errors=True)
os.mkdir(urls_dir)

for url, transformer in trusted_3p:
    name = versionstr(url.encode()) + '.txt'
    with open(os.path.join(urls_dir, name), 'w', encoding='utf-8') as fout:
        fout.write(transformer(get(url).text.strip()))
    content.append(f'url/{name}')

content.sort()
content = '\n'.join(
    map(lambda namestr: '!#include {}/{}'.format(wd, namestr), content))
version = versionstr(content.encode())

with open('external.txt', 'w', encoding='utf-8') as fout:
    fout.write(header_text.format(version=version))
    fout.write('\n\n')
    fout.write(content)
