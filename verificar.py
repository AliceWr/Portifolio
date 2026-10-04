#!/usr/bin/env python3
"""Confere se o site publicado é idêntico ao seu arquivo (detecta alteração/invasão).

    python3 verificar.py https://seusite.com.br SHA256.txt
    python3 verificar.py https://usuario.github.io/repo/ SHA256.txt --so-conteudo   (GitHub Pages)

Sai com código 1 e imprime ALERTA se algo estiver diferente."""
import sys, hashlib, urllib.request
args = [x for x in sys.argv[1:] if not x.startswith('--')]
so_conteudo = '--so-conteudo' in sys.argv
if len(args) < 2: sys.exit('uso: verificar.py URL SHA256.txt [--so-conteudo]')
url, arq = args[0], args[1]
esperado = open(arq).read().split()[0].lower()
req = urllib.request.Request(url, headers={'User-Agent': 'verificador-integridade/1.0', 'Cache-Control': 'no-cache'})
r = urllib.request.urlopen(req, timeout=25)
corpo = r.read()
h = hashlib.sha256(corpo).hexdigest()
H = {k.lower(): v for k, v in r.getheaders()}
falta = [] if so_conteudo else [x for x in ('content-security-policy', 'x-content-type-options', 'x-frame-options') if x not in H]
ok = (h == esperado)
print('Conteúdo :', 'OK, idêntico ao original' if ok else 'ALERTA! DIFERENTE DO ORIGINAL (%s)' % h)
print('Cabeçalhos de segurança:', 'ignorados (--so-conteudo)' if so_conteudo else 'OK' if not falta else 'ALERTA! faltando: ' + ', '.join(falta))
sys.exit(0 if (ok and not falta) else 1)
