#!/usr/bin/env python3
"""hashrelay: a stratum relay with real share hashes (Python standard library only).

Your miner connects here (port 23340) instead of straight to your pool port (for example DATUM Gateway on this
Umbrel). Every byte is passed on unchanged. For each share the pool accepts, hashrelay works out the real
BLAKE2b hash of the share (the hash a block would need to beat) and offers it to the hashes.space dashboard,
so the bits that fly into the block there are the real bits of your miner's work.

It holds no keys, no payout address and no settings of your miner, and it never changes a message. A hash is
only offered after it passes a check against the share difficulty, so a wrong hash is never shown.

  GET  /                 status page and the setting of the pool port to forward to (behind the Umbrel login)
  GET  /api/status       what the relay sees (JSON)
  GET  /api/hashes?since=<seq>   the latest verified share hashes (read by the hashes.space dashboard; no login)
  POST /api/config       {"upstream_host": "...", "upstream_port": 23339}

The hash of a share on the Bitcoin BLAKE2b chain as a pooled miner computes it (header v2, "mode 0": the job's
previous hash has its first 6 bytes zeroed), from Bitcoin Knots src/primitives/block.cpp, CBlockHeader::GetHash:
  stage 1 = BLAKE2b-256( 00 | coinb1 | extranonce1 | extranonce2 | coinb2 )
  stage 2 = BLAKE2b-256( prevhash(32) | nonce(8) | ntime(8) | stage 1 )
"""
import asyncio
import hashlib
import html
import json
import math
import os
import re
import time
from collections import deque
from urllib.parse import parse_qs, urlparse

STRATUM_PORT = int(os.environ.get('STRATUM_PORT', '23340'))
WEB_PORT = int(os.environ.get('PORT', '3000'))
DATA = os.environ.get('DATA_DIR', '/data')
CONFIG_FILE = os.path.join(DATA, 'config.json')
DEFAULTS = {'upstream_host': os.environ.get('UPSTREAM_HOST', 'host.docker.internal'), 'upstream_port': int(os.environ.get('UPSTREAM_PORT', '23339'))}

cfg = dict(DEFAULTS)
try:
    with open(CONFIG_FILE) as f:
        saved = json.load(f)
    if isinstance(saved.get('upstream_host'), str) and isinstance(saved.get('upstream_port'), int):
        cfg.update({'upstream_host': saved['upstream_host'], 'upstream_port': saved['upstream_port']})
except Exception:
    pass

shares = deque(maxlen=1000)          # verified shares: {seq, t, ip, hash, diff}
seq = 0
miners = {}                          # ip -> {since, checked, failed, last, worker, pool}
events = deque(maxlen=30)            # what the status page lists
totals = {'checked': 0, 'failed': 0}


def note(text):
    events.appendleft({'t': time.time(), 'text': text})
    print(time.strftime('%H:%M:%S'), text, flush=True)


def lz_bits(b):
    n = int.from_bytes(b, 'big')
    return 256 - n.bit_length()


def b2b(data):
    return hashlib.blake2b(data, digest_size=32).digest()


def share_hash(job, en1, params):
    """the real hash of a submitted share, or None for a job in another mode"""
    en2, ntime, nonce = params[2], params[3], params[4]
    prev = bytes.fromhex(job['prev'])
    if len(prev) != 32 or any(prev[:6]):
        return None
    stage1 = b2b(b'\x00' + bytes.fromhex(job['c1']) + bytes.fromhex(en1) + bytes.fromhex(en2) + bytes.fromhex(job['c2']))
    return b2b(prev + bytes.fromhex(nonce) + bytes.fromhex(ntime) + stage1).hex()


async def relay(client_r, client_w):
    global seq
    peer = client_w.get_extra_info('peername')
    ip = peer[0].replace('::ffff:', '') if peer else None
    try:
        pool_r, pool_w = await asyncio.wait_for(asyncio.open_connection(cfg['upstream_host'], cfg['upstream_port']), 10)
    except Exception as e:
        note(f"cannot reach the pool port {cfg['upstream_host']}:{cfg['upstream_port']} ({e.__class__.__name__})")
        client_w.close()
        return
    st = {'en1': '', 'jobs': {}, 'diff': 1.0, 'pending': {}}
    m = miners.setdefault(ip, {'since': time.time(), 'checked': 0, 'failed': 0, 'last': 0, 'worker': '', 'pool': f"{cfg['upstream_host']}:{cfg['upstream_port']}"}) if ip else None

    def on_miner(msg):
        if msg.get('method') == 'mining.authorize' and m is not None and msg.get('params'):
            m['worker'] = str(msg['params'][0])[:60]
        if msg.get('method') == 'mining.submit' and isinstance(msg.get('params'), list) and len(msg['params']) >= 5:
            job = st['jobs'].get(str(msg['params'][1]))
            h = None
            try:
                if job and st['en1']:
                    h = share_hash(job, st['en1'], msg['params'])
            except Exception:
                h = None
            st['pending'][msg.get('id')] = (h, st['diff'])

    def on_pool(msg):
        global seq
        method = msg.get('method')
        if method == 'mining.set_difficulty':
            try:
                st['diff'] = float(msg['params'][0]) or st['diff']
            except Exception:
                pass
        elif method == 'mining.notify' and isinstance(msg.get('params'), list):
            p = msg['params']
            st['jobs'][str(p[0])] = {'prev': str(p[1]), 'c1': str(p[2] or ''), 'c2': str(p[3] or '')}
            while len(st['jobs']) > 32:
                st['jobs'].pop(next(iter(st['jobs'])))
        elif msg.get('id') in st['pending']:
            h, diff = st['pending'].pop(msg['id'])
            if msg.get('result') is True and h:
                # a share that meets difficulty D has about 32 + log2(D) leading zero bits; a wrong layout is nowhere near
                need = 32 + math.floor(math.log2(max(1.0, diff))) - 3
                bits = lz_bits(bytes.fromhex(h))
                if bits >= need:
                    seq += 1
                    shares.append({'seq': seq, 't': int(time.time() * 1000), 'ip': ip, 'hash': h, 'diff': diff})
                    totals['checked'] += 1
                    if m is not None:
                        m['checked'] += 1
                        m['last'] = time.time()
                else:
                    totals['failed'] += 1
                    if m is not None:
                        m['failed'] += 1
                    note(f'a share hash failed the check ({bits} zero bits, {need} needed at difficulty {diff:g})')
        elif isinstance(msg.get('result'), list) and len(msg['result']) >= 2 and isinstance(msg['result'][1], str) and msg.get('id') is not None:
            st['en1'] = msg['result'][1]   # the reply to mining.subscribe: [[subscriptions], extranonce1, extranonce2_size]

    async def pump(src, dst, handle):
        buf = b''
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
                buf += data
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        handle(json.loads(line))
                    except Exception:
                        pass   # the relay never breaks the connection
                if len(buf) > 1 << 20:
                    buf = b''
        except Exception:
            pass

    note(f'miner connected from {ip}')
    t1 = asyncio.ensure_future(pump(client_r, pool_w, on_miner))
    t2 = asyncio.ensure_future(pump(pool_r, client_w, on_pool))
    await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
    for t in (t1, t2):
        t.cancel()
    for w in (client_w, pool_w):
        try:
            w.close()
        except Exception:
            pass
    if ip and m is not None:
        m['since'] = m['since'] if time.time() - m['last'] < 120 else m['since']


# ---------------------------------------------------------------- web page and API
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>hashrelay</title><style>
:root{--bg:#10131c;--card:#1b1f2e;--line:#2b3146;--text:#eef0f6;--muted:#9aa3bd;--ok:#6fd286;--bad:#ff8a80;--link:#1bd8f4}
@media(prefers-color-scheme:light){:root{--bg:#f4f5f9;--card:#fff;--line:#dcdfe9;--text:#161a28;--muted:#5d6580;--ok:#1c8a3a;--bad:#c62828;--link:#0a7f94}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}
main{max-width:760px;margin:0 auto;padding:28px 16px;display:grid;gap:16px}h1{margin:0;font-size:24px}h2{margin:0 0 8px;font-size:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px}.muted{color:var(--muted);font-size:13.5px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.stats b{display:block;font:600 20px ui-monospace,monospace}
.stats span{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
code,.mono{font-family:ui-monospace,monospace;font-size:13px;word-break:break-all}
input{font:inherit;padding:8px 10px;border-radius:6px;border:1px solid var(--line);background:var(--bg);color:var(--text);min-width:0}
button{font:inherit;font-weight:600;padding:8px 14px;border-radius:6px;border:0;background:var(--link);color:#001;cursor:pointer}
form{display:flex;gap:8px;flex-wrap:wrap;align-items:center}ul{margin:0;padding-left:18px}li{margin:3px 0}.ok{color:var(--ok)}.bad{color:var(--bad)}
</style></head><body><main>
<h1>hashrelay</h1>
<p class="muted">A relay between your miner and your pool port. It passes everything on unchanged and works out the real hash of every accepted share for the hashes.space dashboard.</p>
<div class="card"><div class="stats">
<div><b id="miners">–</b><span>miners connected</span></div><div><b id="checked">–</b><span>real hashes</span></div><div><b id="failed">–</b><span>failed the check</span></div></div></div>
<div class="card"><h2>Point your miner here</h2>
<p class="muted">In your miner's pool settings use this Umbrel's address and port <b>__PORT__</b>, with the worker name you use now, for example <code>stratum+tcp://umbrel.local:__PORT__</code> (or the IP address of your Umbrel). Keep your old pool as a second pool: if hashrelay ever stops, the miner falls back to it.</p></div>
<div class="card"><h2>Pool port to forward to</h2>
<form id="f"><input id="h" aria-label="Pool host" value="__HOST__" size="26"><input id="p" aria-label="Pool port" value="__UPPORT__" size="7" inputmode="numeric"><button>Save</button><span id="msg" class="muted"></span></form>
<p class="muted">The stratum address of the pool your miner hashes on now, for example DATUM Gateway on this Umbrel. <code>host.docker.internal</code> is this Umbrel itself.</p></div>
<div class="card"><h2>Miners</h2><ul id="ml"><li class="muted">none yet</li></ul></div>
<div class="card"><h2>Latest events</h2><ul id="ev" class="mono"></ul></div>
<script>
const $=id=>document.getElementById(id);
async function load(){try{const s=await (await fetch('api/status')).json();
$('miners').textContent=s.miners.length;$('checked').textContent=s.checked;$('failed').textContent=s.failed;$('failed').className=s.failed?'bad':'';
$('ml').innerHTML=s.miners.map(m=>'<li><span class="mono">'+esc(m.ip)+'</span> '+esc(m.worker)+' · '+m.checked+' real hashes'+(m.last?' · last '+Math.round(Date.now()/1000-m.last)+' s ago':'')+'</li>').join('')||'<li class="muted">none yet</li>';
$('ev').innerHTML=s.events.map(e=>'<li>'+new Date(e.t*1000).toLocaleTimeString()+' '+esc(e.text)+'</li>').join('');}catch(e){}}
function esc(t){return String(t).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
$('f').onsubmit=async e=>{e.preventDefault();const r=await fetch('api/config',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({upstream_host:$('h').value.trim(),upstream_port:Number($('p').value)})});
const j=await r.json();$('msg').textContent=r.ok?'Saved. New connections use it.':(j.error||'Not saved');};
load();setInterval(load,2000);
</script></main></body></html>"""


def json_resp(obj, status=200):
    body = json.dumps(obj).encode()
    return status, 'application/json', body


async def web(r, w):
    try:
        head = await asyncio.wait_for(r.readuntil(b'\r\n\r\n'), 10)
        lines = head.decode('latin-1').split('\r\n')
        method, target, _ = lines[0].split(' ', 2)
        headers = {}
        for ln in lines[1:]:
            if ':' in ln:
                k, v = ln.split(':', 1)
                headers[k.strip().lower()] = v.strip()
        body = b''
        n = int(headers.get('content-length', '0') or 0)
        if 0 < n <= 4096:
            body = await asyncio.wait_for(r.readexactly(n), 10)
        u = urlparse(target)
        if method == 'GET' and u.path == '/':
            page = PAGE.replace('__PORT__', str(STRATUM_PORT)).replace('__HOST__', html.escape(cfg['upstream_host'], quote=True)).replace('__UPPORT__', str(cfg['upstream_port']))
            status, ctype, out = 200, 'text/html; charset=utf-8', page.encode()
        elif method == 'GET' and u.path == '/api/status':
            status, ctype, out = json_resp({
                'upstream': f"{cfg['upstream_host']}:{cfg['upstream_port']}", 'stratumPort': STRATUM_PORT,
                'checked': totals['checked'], 'failed': totals['failed'],
                'miners': [{'ip': ip, **{k: v for k, v in mm.items() if k in ('worker', 'checked', 'failed', 'last')}} for ip, mm in miners.items()],
                'events': list(events)})
        elif method == 'GET' and u.path == '/api/hashes':
            since = int((parse_qs(u.query).get('since') or ['0'])[0] or 0)
            status, ctype, out = json_resp({'stratumPort': STRATUM_PORT, 'seq': seq, 'shares': [s for s in shares if s['seq'] > since]})
        elif method == 'POST' and u.path == '/api/config':
            try:
                b = json.loads(body or b'{}')
                host, port = str(b['upstream_host']).strip(), int(b['upstream_port'])
                if not re.fullmatch(r'[A-Za-z0-9._-]{1,120}', host) or not 1 <= port <= 65535:
                    raise ValueError
            except Exception:
                status, ctype, out = json_resp({'error': 'A host name or address and a port from 1 to 65535, please.'}, 400)
            else:
                cfg.update({'upstream_host': host, 'upstream_port': port})
                try:
                    with open(CONFIG_FILE, 'w') as f:
                        json.dump(cfg, f)
                except Exception as e:
                    note(f'could not save the setting ({e.__class__.__name__})')
                note(f'pool port set to {host}:{port}')
                status, ctype, out = json_resp({'ok': True})
        else:
            status, ctype, out = 404, 'text/plain', b'not found'
        w.write(f'HTTP/1.1 {status} OK\r\nContent-Type: {ctype}\r\nContent-Length: {len(out)}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n'.encode() + out)
        await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def main():
    os.makedirs(DATA, exist_ok=True)
    await asyncio.start_server(relay, '0.0.0.0', STRATUM_PORT)
    await asyncio.start_server(web, '0.0.0.0', WEB_PORT)
    note(f"hashrelay: stratum on :{STRATUM_PORT}, page on :{WEB_PORT}, forwarding to {cfg['upstream_host']}:{cfg['upstream_port']}")
    await asyncio.Event().wait()


if __name__ == '__main__':
    asyncio.run(main())
