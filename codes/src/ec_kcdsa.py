"""
EC-KCDSA — Algoritmo de Firma Digital Coreano Basado en Certificados
         sobre Curvas Elípticas.

Estándares: ISO/IEC 15946-2, TTAK.KO-12.0015.

Diferencias clave respecto a ECDSA
────────────────────────────────────
• Clave pública:  Q = d⁻¹ · G   (escalar inverso, no d·G)
• Firma:          s = d·(k − w̄) mod n  — no requiere inversa de k
• r:              cadena de bytes  r = H(x₁),  no un entero reducido
• Hash del mensaje: e = H(h_cert ‖ m)  vincula al certificado del firmante

────────────────────────────────────────────────────────────────────
Generación de claves (parámetros de dominio p, E, G, n):
    d      ←R [1, n−1]                  clave privada
    Q      = d⁻¹ · G                    clave pública
    h_cert = H(Qx ‖ Qy)                hash del certificado (simplificado)

Firma (mensaje m, clave privada d, h_cert):
    1.  k  ←R [1, n−1]
    2.  (x₁, y₁) = k · G
    3.  r  = H(x₁)                      (l_H bytes)
    4.  e  = H(h_cert ‖ m)
    5.  w̄  = int(r ⊕ e);  si w̄ ≥ n entonces w̄ ← w̄ − n
    6.  s  = d · (k − w̄) mod n          (reintentar si s = 0)
    Devolver (r, s)

Verificación (mensaje m, firma (r, s), clave pública Q, h_cert):
    1.  Verificar |r| ≤ l_H bytes,  s ∈ [1, n−1]
    2.  e  = H(h_cert ‖ m)
    3.  w̄  = int(r ⊕ e);  si w̄ ≥ n entonces w̄ ← w̄ − n
    4.  X  = s · Q + w̄ · G
    5.  v  = H(x(X))
    6.  Aceptar si v = r

Demostración de correctitud
────────────────────────────
  De (6): s = d(k−w̄) mod n
       ⟹  sd⁻¹ = k−w̄ mod n
       ⟹  k   = sd⁻¹ + w̄ mod n
       ⟹  kG  = s(d⁻¹G) + w̄G = sQ + w̄G = X  ✓
  Por lo tanto  H(x(X)) = H(x(kG)) = r  ✓
────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import hashlib
import secrets
from .ec import Curve, Point, SECP256K1

# Longitud del digest SHA-256 en bytes
_L_H: int = 32


# ──────────────────────────────────────────────────────────────────────
# Funciones auxiliares internas
# ──────────────────────────────────────────────────────────────────────

def _sha256(datos: bytes) -> bytes:
    return hashlib.sha256(datos).digest()


def _x_a_bytes(x: int) -> bytes:
    """Codifica un entero x como cadena de 32 bytes big-endian."""
    return x.to_bytes(32, "big")


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR byte a byte de dos cadenas de igual longitud."""
    return bytes(x ^ y for x, y in zip(a, b))


# ──────────────────────────────────────────────────────────────────────
# API pública
# ──────────────────────────────────────────────────────────────────────

def keygen(curva: Curve = SECP256K1) -> tuple[int, Point, bytes]:
    """
    Genera un par de claves EC-KCDSA sobre *curva*.

    Retorna
    -------
    (d, Q, h_cert)
        d      : int   — clave privada,   d ∈ [1, n−1]
        Q      : Point — clave pública,   Q = d⁻¹ · G
        h_cert : bytes — hash del certificado H(Qx ‖ Qy)  (32 bytes)

    Notas
    -----
    En una PKI real el hash del certificado vincula la identidad del
    firmante, su clave pública y el período de validez.  Aquí se usa
    H(Qx ‖ Qy) como sustituto mínimo que ejercita el algoritmo
    correctamente.
    """
    n = curva.n
    d     = secrets.randbelow(n - 1) + 1   # d ∈ [1, n−1]
    d_inv = pow(d, -1, n)                  # d⁻¹ mod n
    Q     = curva.mul(d_inv, curva.G)
    assert Q is not None

    Qx, Qy = Q
    h_cert = _sha256(_x_a_bytes(Qx) + _x_a_bytes(Qy))
    return d, Q, h_cert


def sign(
    mensaje: bytes,
    d: int,
    h_cert: bytes,
    curva: Curve = SECP256K1,
) -> tuple[bytes, int]:
    """
    Genera una firma EC-KCDSA para *mensaje*.

    Parámetros
    ----------
    mensaje : bytes  — texto plano de longitud arbitraria.
    d       : int    — clave privada del firmante.
    h_cert  : bytes  — hash del certificado vinculado a la clave pública.
    curva   : Curve  — parámetros de dominio (por defecto: secp256k1).

    Retorna
    -------
    (r, s)
        r : bytes — H(x₁), longitud l_H = 32 bytes
        s : int   — escalar, s ∈ [1, n−1]
    """
    n = curva.n

    while True:
        # Paso 1 – nonce aleatorio
        k = secrets.randbelow(n - 1) + 1           # k ∈ [1, n−1]

        # Paso 2 – clave pública efímera
        kG = curva.mul(k, curva.G)
        assert kG is not None
        x1, _ = kG

        # Paso 3 – r = H(x₁)
        r = _sha256(_x_a_bytes(x1))

        # Paso 4 – e = H(h_cert ‖ m)
        e = _sha256(h_cert + mensaje)

        # Paso 5 – w̄ = int(r ⊕ e); reducir mod n si es necesario
        w_bar = int.from_bytes(_xor_bytes(r, e), "big")
        if w_bar >= n:
            w_bar -= n

        # Paso 6 – s = d(k − w̄) mod n
        s = d * (k - w_bar) % n
        if s == 0:
            continue

        return r, s


def verify(
    mensaje: bytes,
    firma: tuple[bytes, int],
    Q: Point,
    h_cert: bytes,
    curva: Curve = SECP256K1,
) -> bool:
    """
    Verifica una firma EC-KCDSA.

    Parámetros
    ----------
    mensaje : bytes        — el mensaje firmado.
    firma   : (r, s)       — r es bytes (salida de H), s es entero.
    Q       : Point        — clave pública del firmante.
    h_cert  : bytes        — hash del certificado del firmante.
    curva   : Curve        — parámetros de dominio.

    Retorna
    -------
    True si la firma es válida, False en caso contrario.
    """
    r, s = firma
    n = curva.n

    # Paso 1 – validación de entradas
    if len(r) > _L_H:
        return False
    if not (1 <= s <= n - 1):
        return False

    # Paso 2 – e = H(h_cert ‖ m)
    e = _sha256(h_cert + mensaje)

    # Paso 3 – w̄ = int(r ⊕ e)
    w_bar = int.from_bytes(_xor_bytes(r, e), "big")
    if w_bar >= n:
        w_bar -= n

    # Paso 4 – X = s·Q + w̄·G
    X = curva.add(curva.mul(s, Q), curva.mul(w_bar, curva.G))
    if X is None:
        return False

    # Pasos 5-6 – v = H(x(X));  aceptar si v = r
    x1, _ = X
    v = _sha256(_x_a_bytes(x1))
    return v == r
