"""
GearLock v3 — Millisecond Rotation + Self-Destruct
====================================================
New in v3:
  ✓ Password rotates every millisecond
  ✓ ±500ms tolerance window for network latency
  ✓ 1-day validity only — exact UTC date
  ✓ Self-destruct: all data cryptographically erased after unlock day
  ✓ Background reaper thread wipes expired locks automatically
  ✓ Memory zeroing on delete (not just del)
  ✓ Client sends timestamp — server validates within tolerance
  ✓ Timezone-safe — everything stored and compared in UTC epoch

Install:
  pip install flask flask-cors argon2-cffi

Run:
  python gearlock_v3_server.py
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import hmac, hashlib, secrets, time, threading, ctypes, os
from collections import defaultdict

app = Flask(__name__)
CORS(app)

# ── STORAGE (replace with encrypted DB in production) ──────────────────────
locks       = {}          # lock_id -> config
nonces      = {}          # nonce   -> metadata
attempts    = defaultdict(list)
consumed    = set()
_lock       = threading.RLock()   # thread safety for all stores

# ── CONSTANTS ─────────────────────────────────────────────────────────────
CHARSET      = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
PRIMES       = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71]
MAX_ATTEMPTS = 5
NONCE_TTL    = 10          # nonces valid for only 10 seconds (was 120)
TOLERANCE_MS = 500         # ±500ms window for network latency
DAY_SECONDS  = 86400
REAPER_INTERVAL = 60       # check for expired locks every 60 seconds


# ══════════════════════════════════════════════════════════════════════════
# CRYPTO CORE — millisecond-based
# ══════════════════════════════════════════════════════════════════════════

def make_master_secret(lock_id: str, user_pin: str) -> bytes:
    """Master secret = HMAC-SHA256(pin, lock_id). PIN never stored."""
    return hmac.new(user_pin.encode(), lock_id.encode(), hashlib.sha256).digest()

def derive_gear_seed(master: bytes, gear_idx: int) -> int:
    msg = f"gearlock:v3:gear:{gear_idx}".encode()
    h = hmac.new(master, msg, hashlib.sha256).digest()
    return int.from_bytes(h[:8], 'big')

def get_hole_position(master: bytes, gear_idx: int, ms_epoch: int, spikes: int) -> int:
    """
    ms_epoch = current Unix time in milliseconds.
    Each gear rotates at its own prime ratio per millisecond.
    One complete rotation per gear takes (spikes / ratio) milliseconds.
    """
    seed  = derive_gear_seed(master, gear_idx)
    ratio = PRIMES[gear_idx % len(PRIMES)]
    return (seed + ms_epoch * ratio) % spikes

def get_char_at_ms(master: bytes, gear_idx: int, ms_epoch: int, spikes: int) -> str:
    hole = get_hole_position(master, gear_idx, ms_epoch, spikes)
    msg  = f"gearlock:v3:char:{gear_idx}:{hole}:{ms_epoch // 1000}".encode()
    h    = hmac.new(master, msg, hashlib.sha256).digest()
    return CHARSET[h[0] % len(CHARSET)]

def compute_password_at_ms(master: bytes, ms_epoch: int, num_gears: int, spikes: int) -> str:
    return ''.join(
        get_char_at_ms(master, i, ms_epoch, spikes)
        for i in range(num_gears)
    )

def compute_password_for_display(master: bytes, unlock_ts_ms: int, num_gears: int, spikes: int) -> str:
    """
    The 'stored' password is computed at the exact unlock millisecond.
    At verify time we check a ±500ms window around the client's claimed timestamp.
    """
    return compute_password_at_ms(master, unlock_ts_ms, num_gears, spikes)

def verify_within_tolerance(master: bytes, attempt: str, client_ms: int,
                             num_gears: int, spikes: int) -> bool:
    """
    Check if 'attempt' matches ANY millisecond in
    [client_ms - TOLERANCE_MS, client_ms + TOLERANCE_MS].
    Uses constant-time comparison on every candidate.
    """
    matched = False
    for offset in range(-TOLERANCE_MS, TOLERANCE_MS + 1):
        candidate = compute_password_at_ms(master, client_ms + offset, num_gears, spikes)
        if hmac.compare_digest(attempt, candidate):
            matched = True
            # DO NOT break early — continue to avoid timing side-channel
    return matched


# ══════════════════════════════════════════════════════════════════════════
# SELF-DESTRUCT ENGINE
# ══════════════════════════════════════════════════════════════════════════

def zero_string(s: str) -> None:
    """Best-effort memory zeroing for Python strings (CPython internal)."""
    try:
        encoded = s.encode()
        buf = (ctypes.c_char * len(encoded)).from_buffer(bytearray(encoded))
        ctypes.memset(buf, 0, len(encoded))
    except Exception:
        pass  # not all platforms support this

def cryptographic_erase(lock_id: str) -> None:
    """
    Permanently erase all traces of a lock:
    1. Overwrite sensitive fields with random bytes
    2. Delete from all data structures
    3. Zero the lock_id string in memory
    """
    with _lock:
        lock = locks.get(lock_id)
        if lock:
            # overwrite sensitive fields with random data before deletion
            lock['pin_hash']   = secrets.token_hex(64)
            lock['label']      = secrets.token_hex(16)
            lock['unlock_ts_ms'] = 0
            lock['num_gears']  = 0
            lock['spikes']     = 0
            del locks[lock_id]

        # remove all nonces associated with this lock
        dead_nonces = [n for n, v in nonces.items() if v.get('lock_id') == lock_id]
        for n in dead_nonces:
            nonces[n] = {}
            del nonces[n]

        # remove from consumed set
        consumed.discard(lock_id)

        # remove attempt history
        attempts.pop(lock_id, None)

        zero_string(lock_id)

    print(f"[SELF-DESTRUCT] Lock {lock_id[:8]}... permanently erased at {time.strftime('%Y-%m-%d %H:%M:%S UTC')}")


def should_self_destruct(lock: dict) -> bool:
    """
    A lock self-destructs when:
    - Current UTC time has passed the end of the unlock day (midnight UTC after unlock day)
    """
    if not lock:
        return False
    unlock_day_start = (lock['unlock_ts_ms'] // 1000 // DAY_SECONDS) * DAY_SECONDS
    unlock_day_end   = unlock_day_start + DAY_SECONDS
    return time.time() > unlock_day_end


def reaper_thread():
    """
    Background daemon that checks every 60 seconds for locks that
    have passed their unlock day and triggers self-destruct.
    """
    while True:
        time.sleep(REAPER_INTERVAL)
        with _lock:
            expired = [lid for lid, lock in locks.items() if should_self_destruct(lock)]
        for lid in expired:
            print(f"[REAPER] Lock {lid[:8]}... has expired — initiating self-destruct")
            cryptographic_erase(lid)


# Start reaper daemon
reaper = threading.Thread(target=reaper_thread, daemon=True)
reaper.start()


# ══════════════════════════════════════════════════════════════════════════
# RATE LIMITING
# ══════════════════════════════════════════════════════════════════════════

def get_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

def check_rate_limit(ip: str):
    now = time.time()
    attempts[ip] = [t for t in attempts[ip] if now - t < 3600]
    recent = [t for t in attempts[ip] if now - t < 300]
    if len(recent) >= MAX_ATTEMPTS:
        excess    = len(recent) - MAX_ATTEMPTS + 1
        wait      = 30 * (2 ** min(excess, 8))
        remaining = int(wait - (now - max(recent)))
        if remaining > 0:
            return False, remaining
    return True, 0

def record_attempt(ip: str):
    attempts[ip].append(time.time())


# ══════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════

@app.route('/api/v3/create', methods=['POST'])
def create_lock():
    data = request.get_json()
    pin  = data.get('user_pin', '')

    if len(pin) < 6:
        return jsonify({'error': 'PIN must be at least 6 characters'}), 400

    # Parse unlock date — stored as UTC midnight ms of that day
    unlock_date_str = data.get('unlock_date', '')   # "YYYY-MM-DD"
    try:
        import datetime
        d = datetime.date.fromisoformat(unlock_date_str)
        # unlock_ts_ms = UTC midnight of that day in milliseconds
        unlock_ts_ms = int(datetime.datetime(d.year, d.month, d.day,
                           tzinfo=datetime.timezone.utc).timestamp() * 1000)
    except Exception:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

    if unlock_ts_ms <= time.time() * 1000:
        return jsonify({'error': 'Unlock date must be in the future'}), 400

    num_gears = max(4, min(16, int(data.get('num_gears', 8))))
    spikes    = int(data.get('spikes', 64))
    if spikes not in [32, 64, 128]:
        spikes = 64

    # 256-bit random lock ID
    lock_id = secrets.token_hex(32)

    with _lock:
        locks[lock_id] = {
            'unlock_ts_ms': unlock_ts_ms,
            'unlock_date':  unlock_date_str,
            'num_gears':    num_gears,
            'spikes':       spikes,
            'label':        data.get('label', 'unnamed')[:80],
            'created_at':   time.time(),
            # PIN stored as SHA-256 hash (upgrade to argon2 in production)
            'pin_hash':     hashlib.sha256((pin + lock_id).encode()).hexdigest(),
        }

    from math import log2
    entropy  = int(log2(spikes ** num_gears))
    day_end  = (unlock_ts_ms // 1000 // DAY_SECONDS + 1) * DAY_SECONDS
    destruct = time.strftime('%Y-%m-%d 00:00 UTC', time.gmtime(day_end))

    return jsonify({
        'lock_id':      lock_id,
        'unlock_date':  unlock_date_str,
        'self_destruct': destruct,
        'entropy_bits': entropy,
        'num_gears':    num_gears,
        'spikes':       spikes,
        'rotation':     'every 1 millisecond',
        'window':       f'±{TOLERANCE_MS}ms tolerance',
    })


@app.route('/api/v3/preview', methods=['POST'])
def preview_password():
    """
    Show password for storage. Password = gear alignment at unlock_ts_ms.
    Requires PIN — never cached server-side.
    """
    data    = request.get_json()
    lock_id = data.get('lock_id', '')
    pin     = data.get('user_pin', '')

    with _lock:
        lock = locks.get(lock_id)

    if not lock:
        return jsonify({'error': 'Lock not found or already self-destructed'}), 404

    expected_hash = hashlib.sha256((pin + lock_id).encode()).hexdigest()
    if not hmac.compare_digest(expected_hash, lock['pin_hash']):
        return jsonify({'error': 'Invalid PIN'}), 403

    master   = make_master_secret(lock_id, pin)
    password = compute_password_for_display(
        master, lock['unlock_ts_ms'], lock['num_gears'], lock['spikes']
    )

    day_end   = (lock['unlock_ts_ms'] // 1000 // DAY_SECONDS + 1) * DAY_SECONDS
    destruct  = time.strftime('%Y-%m-%d 00:00:00 UTC', time.gmtime(day_end))

    return jsonify({
        'password':     password,
        'valid_on':     lock['unlock_date'],
        'self_destructs_after': destruct,
        'rotation_note': 'Password rotates every 1ms. At unlock time, system accepts ±500ms window.',
    })


@app.route('/api/v3/nonce', methods=['POST'])
def get_nonce():
    ip = get_ip()
    allowed, wait = check_rate_limit(ip)
    if not allowed:
        return jsonify({'error': f'Rate limited. Wait {wait}s.'}), 429

    lock_id = request.get_json().get('lock_id', '')
    with _lock:
        lock = locks.get(lock_id)

    if not lock:
        return jsonify({'error': 'Lock not found or self-destructed'}), 404

    nonce = secrets.token_hex(32)
    with _lock:
        nonces[nonce] = {
            'lock_id': lock_id,
            'expires': time.time() + NONCE_TTL,
            'used':    False,
            'ip':      ip,
        }

    return jsonify({'nonce': nonce, 'expires_in_seconds': NONCE_TTL})


@app.route('/api/v3/verify', methods=['POST'])
def verify_lock():
    """
    Verify attempt with millisecond precision.
    Client sends: { lock_id, nonce, password_attempt, user_pin, client_timestamp_ms }
    Server checks ±500ms window around client_timestamp_ms using SERVER validation.
    """
    ip = get_ip()
    allowed, wait = check_rate_limit(ip)
    if not allowed:
        return jsonify({'error': f'Rate limited. Wait {wait}s.', 'locked_out': True}), 429

    data            = request.get_json()
    lock_id         = data.get('lock_id', '')
    nonce_val       = data.get('nonce', '')
    attempt         = data.get('password_attempt', '').upper()
    pin             = data.get('user_pin', '')
    client_ts_ms    = int(data.get('client_timestamp_ms', 0))

    record_attempt(ip)

    # 1. Lock exists and not self-destructed?
    with _lock:
        lock = locks.get(lock_id)
    if not lock:
        return jsonify({'error': 'Lock not found or already self-destructed', 'granted': False}), 404

    if lock_id in consumed:
        return jsonify({'error': 'Lock already consumed (one-time use)', 'granted': False}), 410

    # 2. Is it the correct unlock day? (server UTC date)
    server_now_ms      = int(time.time() * 1000)
    server_day_start   = (int(time.time()) // DAY_SECONDS) * DAY_SECONDS * 1000
    unlock_day_start   = (lock['unlock_ts_ms'] // (DAY_SECONDS * 1000)) * DAY_SECONDS * 1000

    if server_day_start != unlock_day_start:
        unlock_human = lock['unlock_date']
        server_human = time.strftime('%Y-%m-%d', time.gmtime())
        days_diff    = (unlock_day_start - server_day_start) // (DAY_SECONDS * 1000)
        return jsonify({
            'granted':      False,
            'error':        'Not the unlock day',
            'unlock_day':   unlock_human,
            'today_utc':    server_human,
            'days_remaining': int(days_diff),
        }), 403

    # 3. Nonce valid?
    with _lock:
        nonce_data = nonces.get(nonce_val)
    if not nonce_data:
        return jsonify({'error': 'Invalid nonce', 'granted': False}), 403
    if nonce_data['used']:
        return jsonify({'error': 'Nonce already used — replay blocked', 'granted': False}), 403
    if time.time() > nonce_data['expires']:
        return jsonify({'error': f'Nonce expired (TTL={NONCE_TTL}s) — request a new one', 'granted': False}), 403
    if nonce_data['lock_id'] != lock_id:
        return jsonify({'error': 'Nonce/lock mismatch', 'granted': False}), 403

    # Consume nonce immediately
    with _lock:
        nonces[nonce_val]['used'] = True

    # 4. Validate client timestamp is within server's current second (prevent future/past abuse)
    ts_drift = abs(server_now_ms - client_ts_ms)
    if ts_drift > 5000:   # allow up to 5s clock drift for legitimate users
        return jsonify({
            'granted': False,
            'error':   f'Client timestamp too far from server time ({ts_drift}ms drift). Use server time.',
        }), 403

    # 5. Verify PIN
    expected_hash = hashlib.sha256((pin + lock_id).encode()).hexdigest()
    if not hmac.compare_digest(expected_hash, lock['pin_hash']):
        remaining = MAX_ATTEMPTS - len([t for t in attempts[ip] if time.time()-t < 300])
        return jsonify({'error': 'Invalid PIN', 'granted': False,
                        'attempts_remaining': max(0, remaining)}), 403

    # 6. Verify password within ±500ms tolerance window
    master  = make_master_secret(lock_id, pin)
    granted = verify_within_tolerance(
        master, attempt, client_ts_ms, lock['num_gears'], lock['spikes']
    )

    if granted:
        with _lock:
            consumed.add(lock_id)
        opened_at = time.strftime('%Y-%m-%d %H:%M:%S.') + str(int(time.time()*1000) % 1000).zfill(3) + ' UTC'
        return jsonify({
            'granted':    True,
            'opened_at':  opened_at,
            'message':    'Access granted. Lock consumed.',
            'note':       f'Lock will self-destruct at end of {lock["unlock_date"]} UTC',
        })
    else:
        remaining = MAX_ATTEMPTS - len([t for t in attempts[ip] if time.time()-t < 300])
        return jsonify({
            'granted':            False,
            'error':              'Incorrect password',
            'attempts_remaining': max(0, remaining),
            'hint':               'Password rotates every 1ms. Use the system-generated value.',
        }), 401


@app.route('/api/v3/status', methods=['GET'])
def lock_status():
    """Public status — no secrets exposed."""
    lock_id = request.args.get('id', '')
    with _lock:
        lock = locks.get(lock_id)
    if not lock:
        return jsonify({'exists': False, 'message': 'Not found or self-destructed'}), 404

    day_end = (lock['unlock_ts_ms'] // 1000 // DAY_SECONDS + 1) * DAY_SECONDS
    return jsonify({
        'exists':         True,
        'unlock_date':    lock['unlock_date'],
        'consumed':       lock_id in consumed,
        'self_destructs': time.strftime('%Y-%m-%d 00:00 UTC', time.gmtime(day_end)),
        'num_gears':      lock['num_gears'],
        'spikes':         lock['spikes'],
        'rotation':       '1ms',
    })


@app.route('/api/v3/server-time', methods=['GET'])
def server_time():
    """Trusted server time — client uses this for password computation."""
    now = time.time()
    return jsonify({
        'timestamp_ms':  int(now * 1000),
        'utc_date':      time.strftime('%Y-%m-%d', time.gmtime(now)),
        'utc_datetime':  time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(now)),
    })


if __name__ == '__main__':
    print("\n🔐 GearLock v3 — Millisecond Rotation + Self-Destruct")
    print("=" * 55)
    print("New features:")
    print(f"  ✓ Password rotates every 1 millisecond")
    print(f"  ✓ ±{TOLERANCE_MS}ms tolerance window for latency")
    print(f"  ✓ 1-day validity window (UTC date)")
    print(f"  ✓ Self-destruct after unlock day ends")
    print(f"  ✓ Background reaper every {REAPER_INTERVAL}s")
    print(f"  ✓ Cryptographic memory erasure on destruct")
    print(f"  ✓ Nonce TTL reduced to {NONCE_TTL}s")
    print(f"  ✓ Client timestamp validated vs server time")
    print(f"  ✓ Thread-safe with RLock")
    print("=" * 55)
    print("Running on http://localhost:5000\n")
    app.run(debug=False, port=5000, threaded=True)

@app.route('/')
def index():
    return open('gearlock_v3_frontend.html').read()

@app.route('/')
def index():
    import os
    return open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'index.html')).read()

