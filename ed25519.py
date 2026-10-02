"""Pure-Python Ed25519 (RFC 8032) — verification with no third-party crypto dependency.

Web Bot Auth (RFC 9421 HTTP Message Signatures) signs requests with Ed25519, and Python's
stdlib ships no Ed25519 primitive. Fener's hard rule is stdlib-only (no pip), so this is the
RFC 8032 reference construction: SHA-512 (hashlib) over twisted-Edwards curve arithmetic.

It is slow by design (scalar multiplication is the textbook double-and-add), which is fine:
we verify a handful of inbound signatures, not a firehose. `checkvalid` never raises on
malformed input — it returns False — so a spoofed or garbage signature is a clean negative,
never a crash in the request path.

  checkvalid(signature64, message_bytes, public_key32) -> bool
  publickey(secret32) -> bytes32        # for the test harness / own-agent signing
  signature(message, secret32, pub32) -> bytes64
"""

import hashlib

# Curve25519 / Ed25519 constants (RFC 8032, b = 256).
_b = 256
_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493  # group order


def _inv(x):
    return pow(x, _p - 2, _p)


_d = (-121665 * _inv(121666)) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = (x * _I) % _p
    if x % 2 != 0:
        x = _p - x
    return x


_By = 4 * _inv(5) % _p
_Bx = _xrecover(_By)
_B = [_Bx % _p, _By % _p]


# Point arithmetic uses extended homogeneous coordinates (X, Y, Z, T) so the inner loop of a
# scalar multiplication needs no modular inverse — only the final affine conversion does. This
# is ~10x faster than the affine textbook form, which matters because verification is on the
# request path. Affine [x, y] and extended tuples are converted at the boundaries.

def _ext(P):
    x, y = P
    return (x % _p, y % _p, 1, (x * y) % _p)


def _affine(P):
    x, y, z, _t = P
    zi = _inv(z)
    return [(x * zi) % _p, (y * zi) % _p]


def _add_ext(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    A = (y1 - x1) * (y2 - x2) % _p
    Bv = (y1 + x1) * (y2 + x2) % _p
    C = 2 * t1 * t2 * _d % _p
    D = 2 * z1 * z2 % _p
    E = Bv - A
    F = D - C
    G = D + C
    H = Bv + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _scalarmult(P, e):
    Q = (0, 1, 1, 0)  # neutral element in extended coordinates
    N = _ext(P)
    while e > 0:
        if e & 1:
            Q = _add_ext(Q, N)
        N = _add_ext(N, N)
        e >>= 1
    return _affine(Q)


def _edwards(P, Q):
    return _affine(_add_ext(_ext(P), _ext(Q)))


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def _Hint(m):
    h = hashlib.sha512(m).digest()
    return sum(2 ** i * _bit(h, i) for i in range(2 * _b))


def _encodeint(y):
    return int(y).to_bytes(_b // 8, "little")


def _encodepoint(P):
    x, y = P
    bits = [(y >> i) & 1 for i in range(_b - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(_b // 8))


def _secret_scalar(sk):
    h = hashlib.sha512(sk).digest()
    a = 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))
    return a, h


def publickey(sk):
    """Derive the 32-byte Ed25519 public key from a 32-byte secret seed."""
    a, _ = _secret_scalar(sk)
    return _encodepoint(_scalarmult(_B, a))


def signature(m, sk, pk):
    """Ed25519 signature of message bytes m under secret seed sk / public key pk."""
    a, h = _secret_scalar(sk)
    r = _Hint(h[_b // 8:_b // 4] + m)
    R = _scalarmult(_B, r)
    S = (r + _Hint(_encodepoint(R) + pk + m) * a) % _L
    return _encodepoint(R) + _encodeint(S)


def _isoncurve(P):
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _p == 0


def _decodepoint(s):
    y = int.from_bytes(s, "little") & ((1 << (_b - 1)) - 1)
    x = _xrecover(y)
    if (x & 1) != _bit(s, _b - 1):
        x = _p - x
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("point not on curve")
    return P


def checkvalid(s, m, pk):
    """True iff s (64 bytes) is a valid Ed25519 signature of m under public key pk (32 bytes).

    Returns False — never raises — on any malformed input, so the request path can treat a
    bad signature as a plain negative.
    """
    try:
        s = bytes(s)
        pk = bytes(pk)
        if len(s) != _b // 4 or len(pk) != _b // 8:
            return False
        R = _decodepoint(s[:_b // 8])
        A = _decodepoint(pk)
        S = int.from_bytes(s[_b // 8:_b // 4], "little")
        if S >= _L:
            return False
        h = _Hint(s[:_b // 8] + pk + m)
        return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))
    except Exception:  # noqa: BLE001  (verification must never throw into the handler)
        return False
