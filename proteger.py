#!/usr/bin/env python3
"""Trava o site. Rode SEMPRE depois de editar o index.html:

    python3 proteger.py                      -> (site em docs/index.html) recalcula os hashes da CSP e o SHA256.txt
    python3 proteger.py --foto retrato.png   -> embute a foto (PNG/JPG/WEBP/AVIF) dentro do index.html

Sem dependências. Só usa a biblioteca padrão do Python 3."""
import re, sys, os, base64, hashlib, argparse

ap = argparse.ArgumentParser()
ap.add_argument('--arquivo')
ap.add_argument('--foto')
a = ap.parse_args()
raiz = os.path.dirname(os.path.abspath(__file__))
padrao = a.arquivo is None
if padrao: a.arquivo = os.path.join(raiz, 'docs', 'index.html')
base = os.path.dirname(os.path.abspath(a.arquivo))
MAX = 2 * 1024 * 1024  # 2 MB

def tipo(b):
    if b[:8] == b'\x89PNG\r\n\x1a\n': return 'png'
    if b[:3] == b'\xff\xd8\xff': return 'jpeg'
    if b[:4] == b'RIFF' and b[8:12] == b'WEBP': return 'webp'
    if b[4:12] == b'ftypavif': return 'avif'
    return None

s = open(a.arquivo, encoding='utf-8').read()

if a.foto:
    b = open(a.foto, 'rb').read()
    t = tipo(b)
    if not t: sys.exit('ERRO: o arquivo não é uma imagem PNG/JPG/WEBP/AVIF de verdade (verifiquei o conteúdo, não só a extensão).')
    if len(b) > MAX: sys.exit('ERRO: a foto passa de 2 MB. Reduza o tamanho (ex.: 1200 px de altura).')
    uri = 'data:image/%s;base64,%s' % (t, base64.b64encode(b).decode())
    s, n = re.subn(r"var FOTO_DATA='[^']*';", lambda m: "var FOTO_DATA='" + uri + "';", s)
    if n != 1: sys.exit("ERRO: não achei 'var FOTO_DATA' no index.html.")
    print('Foto embutida (%s, %d KB).' % (t, len(b) // 1024))

# hash de cada <script> inline (sem src)
scripts = re.findall(r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', s, re.S)
hs = ["'sha256-%s'" % base64.b64encode(hashlib.sha256(t.encode('utf-8')).digest()).decode() for t in scripts]
pol = "script-src 'self' " + ' '.join(hs) + ";"

def aplicar(txt):
    return re.sub(r"script-src [^;]*;", lambda m: pol, txt)

s2 = aplicar(s)
open(a.arquivo, 'w', encoding='utf-8', newline='\n').write(s2)
alvos = [os.path.join(base, '_headers'), os.path.join(raiz, 'extras', 'apache', '.htaccess') if padrao else os.path.join(base, '.htaccess')]
for p in alvos:
    nome = os.path.relpath(p, raiz) if padrao else os.path.basename(p)
    if os.path.exists(p):
        t = open(p, encoding='utf-8').read()
        open(p, 'w', encoding='utf-8', newline='\n').write(aplicar(t))
        print('CSP atualizada em', nome)

h = hashlib.sha256(open(a.arquivo, 'rb').read()).hexdigest()
open(os.path.join(raiz if padrao else base, 'SHA256.txt'), 'w').write('%s  %s\n' % (h, os.path.basename(a.arquivo)))
print('%d scripts autorizados por hash. SHA-256 do site: %s' % (len(hs), h))
print('Guarde o SHA256.txt FORA da hospedagem e suba o index.html atualizado.')
