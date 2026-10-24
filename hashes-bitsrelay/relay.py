#!/usr/bin/env python3
"""bitsrelay: a stratum relay with real share hashes (Python standard library only).

Your miner connects here (port 23340) instead of straight to your pool port (for example DATUM Gateway on this
Umbrel). Every byte is passed on unchanged. For each share the pool accepts, bitsrelay works out the real
BLAKE2b hash of the share (the hash a block would need to beat) and offers it to the hashes.space dashboard,
so the bits that fly into the block there are the real bits of your miner's work.

It holds no keys, no payout address and no settings of your miner, and it never changes a message. A hash is
only offered after it passes a check against the share difficulty, so a wrong hash is never shown.

  GET  /                 status page and the setting of the pool port to forward to (behind the Umbrel login)
  GET  /api/status       what the relay sees (JSON)
  GET  /api/hashes?since=<seq>   the latest verified share hashes (read by the hashes.space dashboard; no login)
  POST /api/config       {"upstream_host": "...", "upstream_port": 23339}
  GET  /api/export.xlsx|pdf|csv?from=YYYY-MM-DD&to=YYYY-MM-DD   every accepted share ever relayed, as a download (behind the login)

Every accepted share is kept in /data/shares.db (SQLite): time, worker, miner address, difficulty and, when it passed
the check, its real hash. It is never deleted by bitsrelay.

The hash of a share on the Bitcoin BLAKE2b chain as a pooled miner computes it (header v2, "mode 0": the job's
previous hash has its first 6 bytes zeroed), from Bitcoin Knots src/primitives/block.cpp, CBlockHeader::GetHash:
  stage 1 = BLAKE2b-256( 00 | coinb1 | extranonce1 | extranonce2 | coinb2 )
  stage 2 = BLAKE2b-256( prevhash(32) | nonce(8) | ntime(8) | stage 1 )
"""
import asyncio
import calendar
import hashlib
import html
import json
import math
import os
import re
import sqlite3
import tempfile
import time
import zipfile
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
totals = {'checked': 0, 'failed': 0, 'rejected': 0, 'stale': 0}
latest = {'prev': None, 't': 0}      # the previous-block hash of the newest job the pool sent: the block being hashed now

# ---------------------------------------------------------------- the record of every accepted share
DB_FILE = os.path.join(DATA, 'shares.db')
pending = []                         # rows waiting for the next write to disk
stored = {'count': 0, 'first': None, 'verified': 0, 'rejected': 0, 'stale': 0}
db = None


def db_connect():
    c = sqlite3.connect(DB_FILE, timeout=30, check_same_thread=False)
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA synchronous=NORMAL')
    return c


def db_init():
    global db
    os.makedirs(DATA, exist_ok=True)
    db = db_connect()
    db.execute('CREATE TABLE IF NOT EXISTS shares (id INTEGER PRIMARY KEY AUTOINCREMENT, t INTEGER NOT NULL, worker TEXT, ip TEXT, diff REAL, hash TEXT, verified INTEGER NOT NULL)')
    db.execute('CREATE INDEX IF NOT EXISTS shares_t ON shares (t)')
    cols = [r[1] for r in db.execute('PRAGMA table_info(shares)')]
    if 'prev' not in cols:       # the block a share belongs to: the previous-block hash of the job it was made on
        db.execute('ALTER TABLE shares ADD COLUMN prev TEXT')
    if 'status' not in cols:     # accepted | rejected | stale (the pool's answer to the share)
        db.execute("ALTER TABLE shares ADD COLUMN status TEXT NOT NULL DEFAULT 'accepted'")
    if 'reason' not in cols:     # what the pool said about a share it did not accept
        db.execute('ALTER TABLE shares ADD COLUMN reason TEXT')
    db.execute('CREATE INDEX IF NOT EXISTS shares_prev ON shares (prev)')
    db.commit()
    n, first, ver, rej, stale = db.execute("SELECT COALESCE(SUM(status='accepted'),0), MIN(t), COALESCE(SUM(verified),0), COALESCE(SUM(status='rejected'),0), COALESCE(SUM(status='stale'),0) FROM shares").fetchone()
    stored.update({'count': n, 'first': first, 'verified': ver, 'rejected': rej, 'stale': stale})


def record(t_ms, worker, ip, diff, h, prev=None, status='accepted', reason=None):
    """one share and the pool's answer to it. h: its hash when it passed the check (an accepted share), or the hash as computed for a share the pool did not accept"""
    ok = status == 'accepted' and bool(h)
    pending.append((t_ms, worker, ip, diff, h, 1 if ok else 0, prev, status, (reason or '')[:160] or None))
    if status == 'accepted':
        stored['count'] += 1
        stored['verified'] += 1 if ok else 0
    elif status in stored:
        stored[status] += 1
    if stored['first'] is None:
        stored['first'] = t_ms


def flush():
    if not pending or db is None:
        return
    rows = pending[:]
    del pending[:len(rows)]
    try:
        db.executemany('INSERT INTO shares (t, worker, ip, diff, hash, verified, prev, status, reason) VALUES (?,?,?,?,?,?,?,?,?)', rows)
        db.commit()
    except Exception as e:
        pending[:0] = rows      # try again next time; nothing is dropped
        note(f'could not write the shares to disk ({e.__class__.__name__})')


async def flusher():
    while True:
        await asyncio.sleep(1)
        flush()


def note(text):
    events.appendleft({'t': time.time(), 'text': text})
    print(time.strftime('%H:%M:%S'), text, flush=True)


def error_text(err):
    """the pool's words for a share it did not accept: [code, "message", data], {"message": ...} or a plain string"""
    try:
        if isinstance(err, list) and len(err) >= 2:
            return f'{err[1]} (code {err[0]})'[:160]
        if isinstance(err, dict):
            return str(err.get('message') or err)[:160]
        if err:
            return str(err)[:160]
    except Exception:
        pass
    return 'rejected by the pool'


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
    st = {'en1': '', 'jobs': {}, 'diff': 1.0, 'pending': {}, 'worker': ''}
    m = miners.setdefault(ip, {'since': time.time(), 'checked': 0, 'failed': 0, 'rejected': 0, 'stale': 0, 'last': 0, 'worker': '', 'pool': f"{cfg['upstream_host']}:{cfg['upstream_port']}"}) if ip else None

    def on_miner(msg):
        if msg.get('method') == 'mining.authorize' and m is not None and msg.get('params'):
            m['worker'] = str(msg['params'][0])[:60]
        if msg.get('method') == 'mining.authorize' and msg.get('params'):
            st['worker'] = str(msg['params'][0])[:90]
        if msg.get('method') == 'mining.submit' and isinstance(msg.get('params'), list) and len(msg['params']) >= 5:
            job = st['jobs'].get(str(msg['params'][1]))
            h = None
            try:
                if job and st['en1']:
                    h = share_hash(job, st['en1'], msg['params'])
            except Exception:
                h = None
            st['pending'][msg.get('id')] = (h, st['diff'], job['prev'] if job else None)

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
            latest.update({'prev': str(p[1]), 't': time.time()})
            while len(st['jobs']) > 32:
                st['jobs'].pop(next(iter(st['jobs'])))
        elif msg.get('id') in st['pending']:
            h, diff, jprev = st['pending'].pop(msg['id'])
            if msg.get('result') is True:
                good = None
                if h:
                    # a share that meets difficulty D has about 32 + log2(D) leading zero bits; a wrong layout is nowhere near
                    need = 32 + math.floor(math.log2(max(1.0, diff))) - 3
                    bits = lz_bits(bytes.fromhex(h))
                    if bits >= need:
                        good = h
                        seq += 1
                        shares.append({'seq': seq, 't': int(time.time() * 1000), 'ip': ip, 'hash': h, 'diff': diff, 'prev': jprev})
                        totals['checked'] += 1
                        if m is not None:
                            m['checked'] += 1
                            m['last'] = time.time()
                    else:
                        totals['failed'] += 1
                        if m is not None:
                            m['failed'] += 1
                        note(f'a share hash failed the check ({bits} zero bits, {need} needed at difficulty {diff:g})')
                # every accepted share is kept; its hash only when it passed the check
                record(int(time.time() * 1000), st['worker'], ip, diff, good, jprev)
            else:
                # the pool did not accept it: kept too, with what the pool said (a stale share is one for a job that is no longer current)
                reason = error_text(msg.get('error'))
                kind = 'stale' if re.search(r'stale|job not found|unknown job|expired|old job|no such job', reason, re.I) else 'rejected'
                record(int(time.time() * 1000), st['worker'], ip, diff, h, jprev, kind, reason)
                totals[kind] = totals.get(kind, 0) + 1
                if m is not None:
                    m[kind] = m.get(kind, 0) + 1
                note(f'a share was {kind}: {reason}')
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


# ---------------------------------------------------------------- downloads: Excel, PDF, CSV
def day_bounds(q):
    """?from=YYYY-MM-DD&to=YYYY-MM-DD (UTC, both days included) as milliseconds"""
    def one(name, end):
        v = (q.get(name) or [''])[0]
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', v):
            return None
        t = calendar.timegm(time.strptime(v, '%Y-%m-%d'))
        return int((t + (86400 if end else 0)) * 1000) - (1 if end else 0)
    return one('from', False), one('to', True)


def where(t0, t1, prev=None):
    cond, args = [], []
    if prev is not None:
        cond.append('prev = ?')
        args.append(prev)
    if t0 is not None:
        cond.append('t >= ?')
        args.append(t0)
    if t1 is not None:
        cond.append('t <= ?')
        args.append(t1)
    return (' WHERE ' + ' AND '.join(cond)) if cond else '', args


def utc(t_ms, fmt='%Y-%m-%d %H:%M:%S'):
    return time.strftime(fmt, time.gmtime(t_ms / 1000))


def wsql(anon):
    """the worker of a share; in the open per-block downloads only its last 6 characters (a worker is usually a payout address)"""
    return "CASE WHEN worker IS NULL OR worker='' THEN '(unknown)' ELSE '...'||substr(worker,-6) END" if anon else "COALESCE(NULLIF(worker,''),'(unknown)')"


def diff_info(con, w, a):
    """the share difficulty over a period: lowest, highest and how often it changed (the pool can change it mid-block)"""
    try:
        lo, hi, ch = con.execute(f"SELECT MIN(diff), MAX(diff), COALESCE(SUM(diff != pd), 0) FROM (SELECT diff, LAG(diff) OVER (ORDER BY id) pd FROM shares{w})", a).fetchone()
        return {'min': lo, 'max': hi, 'changes': int(ch or 0)}
    except sqlite3.Error:
        return {'min': None, 'max': None, 'changes': 0}


def diff_text(d):
    if d['min'] is None:
        return '-'
    if d['min'] == d['max']:
        return f"{d['min']:,.0f} (no change)"
    return f"{d['min']:,.0f} to {d['max']:,.0f}, changed {d['changes']} times"


def summary(con, t0, t1, prev=None, anon=False):
    w, a = where(t0, t1, prev)
    wa = (w + ' AND' if w else ' WHERE') + " status='accepted'"
    n, ver, work, rej, stale, first, last = con.execute(f"SELECT COALESCE(SUM(status='accepted'),0), COALESCE(SUM(verified),0), COALESCE(SUM(CASE WHEN status='accepted' THEN diff ELSE 0 END),0), COALESCE(SUM(status='rejected'),0), COALESCE(SUM(status='stale'),0), MIN(t), MAX(t) FROM shares{w}", a).fetchone()
    workers = con.execute(f"SELECT {wsql(anon)}, SUM(status='accepted'), SUM(verified), SUM(CASE WHEN status='accepted' THEN diff ELSE 0 END), SUM(status='rejected'), SUM(status='stale'), MIN(t), MAX(t) FROM shares{w} GROUP BY 1 ORDER BY 2 DESC", a).fetchall()
    days = con.execute(f"SELECT strftime('%Y-%m-%d', t/1000, 'unixepoch') d, SUM(status='accepted'), SUM(verified), SUM(CASE WHEN status='accepted' THEN diff ELSE 0 END), SUM(status!='accepted') FROM shares{w} GROUP BY d ORDER BY d", a).fetchall()
    best = con.execute(f"SELECT hash, t, {wsql(anon)}, diff FROM shares{wa} AND hash IS NOT NULL ORDER BY hash ASC LIMIT 10", a).fetchall()
    return {'n': n, 'ver': ver, 'work': work, 'rej': rej, 'stale': stale, 'first': first, 'last': last, 'workers': workers, 'days': days, 'best': best, 'diff': diff_info(con, w, a)}


def period_text(t0, t1, s):
    if s['first'] is None:
        return 'no shares in this period'
    return f"{utc(s['first'])} to {utc(s['last'])} UTC"


# --- CSV
def build_csv(path, t0, t1, prev=None, label=None, anon=False):
    con = db_connect()
    w, a = where(t0, t1, prev)
    with open(path, 'w', newline='') as f:
        f.write('number,time_utc,worker,miner_address,difficulty,hash,zero_bits,hash_verified,status,reason\r\n')
        for i, (t, wk, ip, d, h, v, st_, rs) in enumerate(con.execute(f"SELECT t, {wsql(anon)}, {'NULL' if anon else 'ip'}, diff, hash, verified, status, reason FROM shares{w} ORDER BY id", a), 1):
            f.write(f'{i},{utc(t)},"{(wk or "").replace(chr(34), "")}",{ip or ""},{d:g},{h or ""},{lz_bits(bytes.fromhex(h)) if h else ""},{"yes" if v else "no"},{st_},"{(rs or "").replace(chr(34), "")}"\r\n')
    con.close()


# --- Excel (.xlsx written by hand: it is a zip of small XML files)
def xesc(t):
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', html.escape(str(t), quote=False))


def col(n):
    s = ''
    while True:
        n, r = divmod(n, 26)
        s = chr(65 + r) + s
        if n == 0:
            return s
        n -= 1


def xrow(r, cells):
    out = [f'<row r="{r}">']
    for c, v in enumerate(cells):
        if v is None or v == '':
            continue
        ref = f'{col(c)}{r}'
        if isinstance(v, tuple):          # (kind, value): 'b' bold text, 'd' date-time
            kind, val = v
            if kind == 'd':
                out.append(f'<c r="{ref}" s="2"><v>{val / 86400000 + 25569:.8f}</v></c>')
            else:
                out.append(f'<c r="{ref}" s="1" t="inlineStr"><is><t>{xesc(val)}</t></is></c>')
        elif isinstance(v, (int, float)):
            out.append(f'<c r="{ref}"><v>{v!r}</v></c>')
        else:
            out.append(f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{xesc(v)}</t></is></c>')
    out.append('</row>')
    return ''.join(out)


SHEET_OPEN = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
MAX_ROWS = 1_000_000                   # a sheet holds 1,048,576 rows; the next sheet takes over after this many


def build_xlsx(path, t0, t1, prev=None, label=None, anon=False):
    con = db_connect()
    s = summary(con, t0, t1, prev, anon)
    w, a = where(t0, t1, prev)
    names = ['Summary']
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        # Summary sheet
        r = 1
        rows = [[('b', label or 'bitsrelay: shares relayed')], ['Period', period_text(t0, t1, s)], ['Generated', utc(time.time() * 1000) + ' UTC (days below are UTC days)'], [],
                [('b', 'Accepted shares'), s['n']], [('b', 'With a verified real hash'), s['ver']], [('b', 'Rejected shares'), s['rej']], [('b', 'Stale shares'), s['stale']], [('b', 'Total difficulty (work)'), s['work']], [('b', 'Share difficulty at the time'), diff_text(s['diff'])], [],
                [('b', 'Per worker')], [('b', 'Worker'), ('b', 'Accepted'), ('b', 'Verified hashes'), ('b', 'Total difficulty'), ('b', 'Rejected'), ('b', 'Stale'), ('b', 'First share'), ('b', 'Last share')]]
        for wk, n, v, d, rj, stl, f, l in s['workers']:
            rows.append([wk, n or 0, v or 0, d or 0, rj or 0, stl or 0, ('d', f), ('d', l)])
        rows += [[], [('b', 'Per day (UTC)')], [('b', 'Day'), ('b', 'Accepted'), ('b', 'Verified hashes'), ('b', 'Total difficulty'), ('b', 'Rejected or stale')]]
        for d, n, v, df, rj in s['days']:
            rows.append([d, n or 0, v or 0, df or 0, rj or 0])
        rows += [[], [('b', 'Best 10 hashes (most leading zeros)')], [('b', 'Hash'), ('b', 'Time (UTC)'), ('b', 'Worker'), ('b', 'Difficulty')]]
        for h, t, wk, d in s['best']:
            rows.append([h, ('d', t), wk, d])
        with z.open('xl/worksheets/sheet1.xml', 'w') as f:
            f.write((SHEET_OPEN + '<cols><col min="1" max="1" width="30" customWidth="1"/><col min="2" max="8" width="20" customWidth="1"/></cols><sheetData>').encode())
            for i, row in enumerate(rows, 1):
                f.write(xrow(i, row).encode())
            f.write(b'</sheetData></worksheet>')
        # the shares: every one, in as many sheets as it takes
        head = [('b', x) for x in ('#', 'Time (UTC)', 'Worker', 'Miner address', 'Difficulty', 'Hash', 'Zero bits', 'Hash verified', 'Status', 'Reason')]
        cur = con.execute(f"SELECT t, {wsql(anon)}, {'NULL' if anon else 'ip'}, diff, hash, verified, status, reason FROM shares{w} ORDER BY id", a)
        k, sheet, f, r = 0, 1, None, 0
        for k, (t, wk, ip, d, h, v, st_, rs) in enumerate(cur, 1):
            if f is None or r > MAX_ROWS:
                if f is not None:
                    f.write(b'</sheetData></worksheet>')
                    f.close()
                sheet += 1
                names.append(f'Shares {sheet - 1}')
                f = z.open(f'xl/worksheets/sheet{sheet}.xml', 'w')
                f.write((SHEET_OPEN + '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
                         '<cols><col min="1" max="1" width="10" customWidth="1"/><col min="2" max="2" width="20" customWidth="1"/><col min="3" max="4" width="24" customWidth="1"/><col min="5" max="5" width="12" customWidth="1"/><col min="6" max="6" width="68" customWidth="1"/><col min="7" max="8" width="12" customWidth="1"/><col min="9" max="9" width="12" customWidth="1"/><col min="10" max="10" width="40" customWidth="1"/></cols><sheetData>').encode())
                f.write(xrow(1, head).encode())
                r = 1
            r += 1
            f.write(xrow(r, [k, ('d', t), wk or '', ip or '', d, h or '', lz_bits(bytes.fromhex(h)) if h else '', 'yes' if v else 'no', st_, rs or '']).encode())
        if f is not None:
            f.write(b'</sheetData></worksheet>')
            f.close()
        if len(names) == 1:
            names.append('Shares 1')
            z.writestr('xl/worksheets/sheet2.xml', SHEET_OPEN + '<sheetData>' + xrow(1, head) + '</sheetData></worksheet>')
        n = len(names)
        z.writestr('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
                   + ''.join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(1, n + 1)) + '</Types>')
        z.writestr('_rels/.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr('xl/workbook.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
                   + ''.join(f'<sheet name="{nm}" sheetId="{i}" r:id="rId{i}"/>' for i, nm in enumerate(names, 1)) + '</sheets></workbook>')
        z.writestr('xl/_rels/workbook.xml.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   + ''.join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1, n + 1))
                   + f'<Relationship Id="rId{n + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
        z.writestr('xl/styles.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy\\-mm\\-dd\\ hh:mm:ss"/></numFmts>'
                   '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>'
                   '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
                   '<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/><xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>')
    con.close()


# --- PDF (a plain, text-only PDF written by hand: the totals, not every hash; the Excel file has every hash)
class Pdf:
    W, H, M = 595, 842, 48

    def __init__(self):
        self.pages = []
        self.y = 0
        self.newpage()

    def newpage(self):
        self.pages.append([])
        self.y = self.H - self.M

    def text(self, x, s, font='F1', size=10, lead=None):
        s = str(s).encode('latin-1', 'replace').decode('latin-1').replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        self.pages[-1].append(f'BT /{font} {size} Tf {x} {self.y:.1f} Td ({s}) Tj ET')

    def line(self, cols, xs, font='F1', size=10):
        if self.y < self.M + 20:
            self.newpage()
        for x, c in zip(xs, cols):
            self.text(x, c, font, size)
        self.y -= size + 5

    def gap(self, n=8):
        self.y -= n

    def save(self, path):
        objs = []
        pages = len(self.pages)
        objs.append('<< /Type /Catalog /Pages 2 0 R >>')
        objs.append('<< /Type /Pages /Kids [' + ' '.join(f'{6 + 2 * i} 0 R' for i in range(pages)) + f'] /Count {pages} >>')
        for font in ('Helvetica', 'Helvetica-Bold', 'Courier'):
            objs.append(f'<< /Type /Font /Subtype /Type1 /BaseFont /{font} /Encoding /WinAnsiEncoding >>')
        objs.append(None)   # placeholder to keep the numbering: object 6 is the first page
        objs.pop()
        for i, items in enumerate(self.pages):
            foot = f'BT /F1 8 Tf {self.M} 24 Td (bitsrelay  -  page {i + 1} of {pages}) Tj ET'
            stream = '\n'.join(items + [foot])
            objs.append(f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.W} {self.H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents {7 + 2 * i} 0 R >>')
            objs.append(f'<< /Length {len(stream.encode("latin-1", "replace"))} >>\nstream\n{stream}\nendstream')
        out = bytearray(b'%PDF-1.4\n')
        offs = []
        for i, o in enumerate(objs, 1):
            offs.append(len(out))
            out += f'{i} 0 obj\n{o}\nendobj\n'.encode('latin-1', 'replace')
        x = len(out)
        out += f'xref\n0 {len(objs) + 1}\n0000000000 65535 f \n'.encode()
        for o in offs:
            out += f'{o:010d} 00000 n \n'.encode()
        out += f'trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n'.encode()
        with open(path, 'wb') as f:
            f.write(out)


def build_pdf(path, t0, t1, prev=None, label=None, anon=False):
    con = db_connect()
    s = summary(con, t0, t1, prev, anon)
    con.close()
    p = Pdf()
    M = p.M
    p.text(M, label or 'bitsrelay: shares relayed', 'F2', 20)
    p.y -= 26
    p.line([f'Period: {period_text(t0, t1, s)}'], [M])
    p.line([f"Generated: {utc(time.time() * 1000)} UTC. Days are UTC days."], [M])
    p.gap(10)
    p.line(['Accepted shares'], [M], 'F2', 11)
    p.line(['Total', f"{s['n']:,}"], [M, 230], 'F2', 14)
    p.line(['With a verified real hash', f"{s['ver']:,}"], [M, 230])
    p.line(['Rejected shares', f"{s['rej']:,}"], [M, 230])
    p.line(['Stale shares', f"{s['stale']:,}"], [M, 230])
    p.line(['Total difficulty (work)', f"{s['work']:,.0f}"], [M, 230])
    p.line(['Share difficulty at the time', diff_text(s['diff'])], [M, 230])
    p.gap(12)
    p.line(['Per worker'], [M], 'F2', 11)
    xs = [M, 190, 245, 300, 375, 420, 480]
    p.line(['Worker', 'Accepted', 'Verified', 'Total difficulty', 'Rejected', 'Stale', 'Last share'], xs, 'F2', 8)
    for wk, n, v, d, rj, stl, f, l in s['workers']:
        p.line([wk[:22], f'{(n or 0):,}', f'{(v or 0):,}', f'{(d or 0):,.0f}', f'{(rj or 0):,}', f'{(stl or 0):,}', utc(l, '%m-%d %H:%M')], xs, 'F1', 8)
    p.gap(12)
    p.line(['Per day (UTC)'], [M], 'F2', 11)
    xs = [M, 150, 230, 310, 420]
    p.line(['Day', 'Accepted', 'Verified', 'Total difficulty', 'Rejected or stale'], xs, 'F2', 9)
    for d, n, v, df, rj in s['days']:
        p.line([d, f'{(n or 0):,}', f'{(v or 0):,}', f'{(df or 0):,.0f}', f'{(rj or 0):,}'], xs, 'F1', 9)
    p.gap(12)
    p.line(['Best 10 hashes (most leading zeros)'], [M], 'F2', 11)
    for h, t, wk, d in s['best']:
        p.line([h], [M], 'F3', 8)
        p.line([f'{utc(t)} UTC, {wk[:30]}, difficulty {d:g}'], [M + 10], 'F1', 8)
    p.gap(10)
    p.line(['Every share with its hash is in the Excel and CSV downloads.'], [M], 'F1', 9)
    p.save(path)


BUILDERS = {'xlsx': (build_xlsx, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'), 'pdf': (build_pdf, 'application/pdf'), 'csv': (build_csv, 'text/csv; charset=utf-8')}


# ---------------------------------------------------------------- web page and API
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>bitsrelay</title><style>
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
a.btn{font-weight:600;padding:8px 14px;border-radius:6px;background:var(--link);color:#001;text-decoration:none}label input{margin-left:4px}
form{display:flex;gap:8px;flex-wrap:wrap;align-items:center}ul{margin:0;padding-left:18px}li{margin:3px 0}.ok{color:var(--ok)}.bad{color:var(--bad)}
</style></head><body><main>
<h1>bitsrelay</h1>
<p class="muted">A relay between your miner and your pool port. It passes everything on unchanged and works out the real hash of every accepted share for the hashes.space dashboard.</p>
<div class="card"><div class="stats">
<div><b id="miners">–</b><span>miners connected</span></div><div><b id="checked">–</b><span>real hashes</span></div><div><b id="failed">–</b><span>failed the check</span></div></div></div>
<div class="card"><h2>Point your miner here</h2>
<p class="muted">In your miner's pool settings use this Umbrel's address and port <b>__PORT__</b>, with the worker name you use now, for example <code>stratum+tcp://umbrel.local:__PORT__</code> (or the IP address of your Umbrel). Keep your old pool as a second pool: if bitsrelay ever stops, the miner falls back to it.</p></div>
<div class="card"><h2>Pool port to forward to</h2>
<form id="f"><input id="h" aria-label="Pool host" value="__HOST__" size="26"><input id="p" aria-label="Pool port" value="__UPPORT__" size="7" inputmode="numeric"><button>Save</button><span id="msg" class="muted"></span></form>
<p class="muted">The stratum address of the pool your miner hashes on now, for example DATUM Gateway on this Umbrel. <code>host.docker.internal</code> is this Umbrel itself.</p></div>
<div class="card"><h2>Your shares</h2>
<p class="muted" id="st">Every share the pool accepts is kept on this Umbrel, with its real hash when it passed the check. Nothing is sent anywhere.</p>
<form id="dl"><label class="muted">From <input type="date" id="df"></label><label class="muted">To <input type="date" id="dt"></label>
<a class="btn" id="x" href="#">Excel</a><a class="btn" id="d" href="#">PDF</a><a class="btn" id="c" href="#">CSV</a></form>
<p class="muted">Leave the dates empty for everything. Days are UTC days. The PDF holds the totals (per worker, per day, best hashes); Excel and CSV hold every share with its hash.</p></div>
<div class="card"><h2>Miners</h2><ul id="ml"><li class="muted">none yet</li></ul></div>
<div class="card"><h2>Latest events</h2><ul id="ev" class="mono"></ul></div>
<script>
const $=id=>document.getElementById(id);
async function load(){try{const s=await (await fetch('api/status')).json();
$('miners').textContent=s.miners.length;$('checked').textContent=s.checked;$('failed').textContent=s.failed;$('failed').className=s.failed?'bad':'';
$('ml').innerHTML=s.miners.map(m=>'<li><span class="mono">'+esc(m.ip)+'</span> '+esc(m.worker)+' · '+m.checked+' real hashes'+(m.last?' · last '+Math.round(Date.now()/1000-m.last)+' s ago':'')+'</li>').join('')||'<li class="muted">none yet</li>';
$('st').textContent=s.stored.toLocaleString()+' accepted shares kept ('+s.storedVerified.toLocaleString()+' with a verified real hash)'+((s.storedRejected||s.storedStale)?', '+(s.storedRejected||0).toLocaleString()+' rejected and '+(s.storedStale||0).toLocaleString()+' stale also kept':'')+(s.storedSince?', since '+new Date(s.storedSince).toLocaleDateString():'')+'. Nothing is sent anywhere.';
$('ev').innerHTML=s.events.map(e=>'<li>'+new Date(e.t*1000).toLocaleTimeString()+' '+esc(e.text)+'</li>').join('');}catch(e){}}
function esc(t){return String(t).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
$('f').onsubmit=async e=>{e.preventDefault();const r=await fetch('api/config',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({upstream_host:$('h').value.trim(),upstream_port:Number($('p').value)})});
const j=await r.json();$('msg').textContent=r.ok?'Saved. New connections use it.':(j.error||'Not saved');};
function links(){const q=(($('df').value?'from='+$('df').value:'')+($('dt').value?'&to='+$('dt').value:'')).replace(/^&/,'');
for(const [id,k] of [['x','xlsx'],['d','pdf'],['c','csv']])$(id).href='api/export.'+k+(q?'?'+q:'');}
$('df').onchange=$('dt').onchange=links;links();
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
                'stored': stored['count'], 'storedVerified': stored['verified'], 'storedRejected': stored['rejected'], 'storedStale': stored['stale'], 'storedSince': stored['first'],
                'miners': [{'ip': ip, **{k: v for k, v in mm.items() if k in ('worker', 'checked', 'failed', 'last')}} for ip, mm in miners.items()],
                'events': list(events)})
        elif method == 'GET' and u.path == '/api/hashes':
            since = int((parse_qs(u.query).get('since') or ['0'])[0] or 0)
            status, ctype, out = json_resp({'stratumPort': STRATUM_PORT, 'seq': seq, 'shares': [s for s in shares if s['seq'] > since]})
        elif method == 'GET' and u.path == '/api/hashes/rounds':
            # the blocks the shares were made for (a round = all shares on jobs that build on the same previous block), newest first
            flush()
            lim = max(1, min(200, int((parse_qs(u.query).get('limit') or ['30'])[0] or 30)))
            con = db_connect()
            rows = con.execute("SELECT prev, SUM(status='accepted'), COALESCE(SUM(verified),0), MIN(t), MAX(t), COALESCE(SUM(CASE WHEN status='accepted' THEN diff ELSE 0 END),0), SUM(status='rejected'), SUM(status='stale') FROM shares WHERE prev IS NOT NULL GROUP BY prev ORDER BY MAX(id) DESC LIMIT ?", (lim,)).fetchall()
            con.close()
            status, ctype, out = json_resp({'current': latest['prev'], 'rounds': [{'prev': p, 'count': n, 'verified': v, 'first': f, 'last': l, 'work': d, 'rejected': rj, 'stale': stl} for p, n, v, f, l, d, rj, stl in rows]})
        elif method == 'GET' and u.path == '/api/hashes/round':
            # every share of one block: newest first (live view) or the ones after an id (?after=)
            q = parse_qs(u.query)
            prev = (q.get('prev') or [''])[0]
            if not re.fullmatch(r'[0-9a-fA-F]{64}', prev):
                status, ctype, out = json_resp({'error': 'prev must be 64 hex characters'}, 400)
            else:
                flush()
                lim = max(1, min(2000, int((q.get('limit') or ['300'])[0] or 300)))
                after = int((q.get('after') or ['0'])[0] or 0)
                con = db_connect()
                n, v, d, f, l, rj, stl = con.execute("SELECT COALESCE(SUM(status='accepted'),0), COALESCE(SUM(verified),0), COALESCE(SUM(CASE WHEN status='accepted' THEN diff ELSE 0 END),0), MIN(t), MAX(t), COALESCE(SUM(status='rejected'),0), COALESCE(SUM(status='stale'),0) FROM shares WHERE prev = ?", (prev,)).fetchone()
                rows = con.execute(f"SELECT id, t, {wsql(True)}, diff, hash, verified, status, reason FROM shares WHERE prev = ? AND id > ? ORDER BY id DESC LIMIT ?", (prev, after, lim)).fetchall()
                dinfo = diff_info(con, ' WHERE prev = ?', (prev,))
                con.close()
                status, ctype, out = json_resp({'prev': prev, 'total': n, 'verified': v, 'work': d, 'first': f, 'last': l, 'rejected': rj, 'stale': stl, 'difficulty': dinfo,
                                                'shares': [{'id': i, 't': t, 'miner': wkr, 'diff': df, 'hash': h, 'bits': lz_bits(bytes.fromhex(h)) if h else None, 'verified': bool(vf), 'status': stt, 'reason': rs} for i, t, wkr, df, h, vf, stt, rs in rows]})
        elif method == 'GET' and re.fullmatch(r'/api/(export|hashes/round)\.(xlsx|pdf|csv)', u.path):
            kind = u.path.rsplit('.', 1)[1]
            fn, ctype = BUILDERS[kind]
            q = parse_qs(u.query)
            t0, t1 = day_bounds(q)
            prev, label, anon, slug = None, None, False, 'shares'
            if u.path.startswith('/api/hashes/round'):
                prev = (q.get('prev') or [''])[0]
                if not re.fullmatch(r'[0-9a-fA-F]{64}', prev):
                    raise ValueError('prev')
                if prev.lower() == (latest['prev'] or '').lower():
                    # the block being hashed has no download: its page is a live view; a block is downloadable once it has been mined
                    w.write(b'HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: 64\r\nConnection: close\r\n\r\n{"error":"The block being hashed can be downloaded once mined."}')
                    await w.drain()
                    return
                anon = True    # open to the dashboard without a login: a worker (a payout address) is cut to its last 6 characters
                label = re.sub(r'[^A-Za-z0-9 #.,:()-]', '', (q.get('label') or [''])[0])[:60].strip() or 'Block shares'
                slug = re.sub(r'[^a-z0-9]+', '-', label.lower()).strip('-') or 'block'
            flush()
            tmp = tempfile.NamedTemporaryFile(dir=tempfile.gettempdir(), suffix='.' + kind, delete=False)
            tmp.close()
            try:
                await asyncio.get_event_loop().run_in_executor(None, lambda: fn(tmp.name, t0, t1, prev, label, anon))
                size = os.path.getsize(tmp.name)
                name = f"bitsrelay-{slug}-{time.strftime('%Y-%m-%d', time.gmtime())}.{kind}"
                w.write(f'HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {size}\r\nContent-Disposition: attachment; filename="{name}"\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n'.encode())
                with open(tmp.name, 'rb') as fh:
                    while True:
                        chunk = fh.read(1 << 20)
                        if not chunk:
                            break
                        w.write(chunk)
                        await w.drain()
                return
            finally:
                try:
                    os.unlink(tmp.name)
                except Exception:
                    pass
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
    db_init()
    asyncio.ensure_future(flusher())
    await asyncio.start_server(relay, '0.0.0.0', STRATUM_PORT)
    await asyncio.start_server(web, '0.0.0.0', WEB_PORT)
    note(f"bitsrelay: stratum on :{STRATUM_PORT}, page on :{WEB_PORT}, forwarding to {cfg['upstream_host']}:{cfg['upstream_port']}")
    await asyncio.Event().wait()


if __name__ == '__main__':
    asyncio.run(main())
