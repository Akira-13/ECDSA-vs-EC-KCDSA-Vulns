#!/usr/bin/env python3
"""
Demo: ECDSA vs EC-KCDSA — implementación from-scratch en Python.

Muestra generación de claves, firma, verificación y detección de
mensajes/firmas alteradas para ambos algoritmos sobre secp256k1.

Uso:
    python main.py
"""

from src.ec import SECP256K1
from src import ecdsa, ec_kcdsa

CURVE = SECP256K1
W = 62   # ancho de línea para separadores


def _sep(char="─"):
    print(char * W)


def _hex(n: int) -> str:
    h = hex(n)
    return h[:20] + "…" if len(h) > 20 else h


def _check(label: str, condition: bool):
    mark = "✓ VÁLIDA   " if condition else "✗ RECHAZADA"
    print(f"  [{mark}]  {label}")


# ──────────────────────────────────────────────────────────────────────
# ECDSA demo
# ──────────────────────────────────────────────────────────────────────

def demo_ecdsa():
    print()
    _sep("═")
    print("  ECDSA  (FIPS 186-5 / ANSI X9.62)")
    print(f"  Curva  : {CURVE.name}  |  Hash: SHA-256")
    _sep("═")

    # --- Generación de claves ---
    d, Q = ecdsa.keygen(CURVE)
    print("\n  [Generación de claves]")
    print(f"    Clave privada  d = {_hex(d)}")
    Qx, Qy = Q  # type: ignore[misc]
    print(f"    Clave pública  Q.x = {_hex(Qx)}")
    print(f"                   Q.y = {_hex(Qy)}")
    print(f"    Q = d·G  ✓" if Q == CURVE.mul(d, CURVE.G) else "    Q = d·G  ✗")

    # --- Firma ---
    mensaje = b"La firma digital protege la integridad del mensaje."
    r, s = ecdsa.sign(mensaje, d, CURVE)
    print(f"\n  [Firmando]  \"{mensaje.decode()}\"")
    print(f"    r = {_hex(r)}")
    print(f"    s = {_hex(s)}")

    # --- Verificación ---
    print("\n  [Verificación]")
    _check("Mensaje original",    ecdsa.verify(mensaje, (r, s), Q, CURVE))
    _check("Mensaje alterado",    ecdsa.verify(b"Mensaje ALTERADO", (r, s), Q, CURVE))
    _check("r modificado (r⊕1)", ecdsa.verify(mensaje, (r ^ 1, s), Q, CURVE))
    _check("s modificado (s⊕1)", ecdsa.verify(mensaje, (r, s ^ 1), Q, CURVE))
    _, Q2 = ecdsa.keygen(CURVE)
    _check("Clave pública ajena", ecdsa.verify(mensaje, (r, s), Q2, CURVE))


# ──────────────────────────────────────────────────────────────────────
# EC-KCDSA demo
# ──────────────────────────────────────────────────────────────────────

def demo_ec_kcdsa():
    print()
    _sep("═")
    print("  EC-KCDSA  (ISO/IEC 15946-2)")
    print(f"  Curva  : {CURVE.name}  |  Hash: SHA-256")
    _sep("═")

    # --- Generación de claves ---
    d, Q, h_cert = ec_kcdsa.keygen(CURVE)
    d_inv = pow(d, -1, CURVE.n)
    print("\n  [Generación de claves]")
    print(f"    Clave privada  d     = {_hex(d)}")
    Qx, Qy = Q  # type: ignore[misc]
    print(f"    Clave pública  Q.x   = {_hex(Qx)}")
    print(f"                   Q.y   = {_hex(Qy)}")
    print(f"    Q = d⁻¹·G  ✓" if Q == CURVE.mul(d_inv, CURVE.G) else "    Q = d⁻¹·G  ✗")
    print(f"    h_cert             = {h_cert.hex()[:20]}…  (H(Q))")

    # --- Firma ---
    mensaje = b"La firma digital protege la integridad del mensaje."
    r, s = ec_kcdsa.sign(mensaje, d, h_cert, CURVE)
    print(f"\n  [Firmando]  \"{mensaje.decode()}\"")
    print(f"    r = {r.hex()[:20]}…  (H(x₁), bytes)")
    print(f"    s = {_hex(s)}")

    # --- Verificación ---
    print("\n  [Verificación]")
    _check("Mensaje original",     ec_kcdsa.verify(mensaje, (r, s), Q, h_cert, CURVE))
    _check("Mensaje alterado",     ec_kcdsa.verify(b"Mensaje ALTERADO", (r, s), Q, h_cert, CURVE))
    bad_r = bytes([r[0] ^ 0xFF]) + r[1:]
    _check("r modificado",         ec_kcdsa.verify(mensaje, (bad_r, s), Q, h_cert, CURVE))
    _check("s modificado (s⊕1)",  ec_kcdsa.verify(mensaje, (r, s ^ 1), Q, h_cert, CURVE))
    _, Q2, h_cert2 = ec_kcdsa.keygen(CURVE)
    _check("Clave pública ajena",  ec_kcdsa.verify(mensaje, (r, s), Q2, h_cert, CURVE))
    _check("h_cert ajeno",         ec_kcdsa.verify(mensaje, (r, s), Q, h_cert2, CURVE))


# ──────────────────────────────────────────────────────────────────────
# Comparison summary
# ──────────────────────────────────────────────────────────────────────

def print_comparison():
    print()
    _sep("═")
    print("  Comparación de propiedades")
    _sep("═")
    rows = [
        ("Propiedad",            "ECDSA",                   "EC-KCDSA"),
        ("─" * 28,               "─" * 22,                  "─" * 22),
        ("Clave pública",        "Q = d·G",                 "Q = d⁻¹·G"),
        ("Forma de r",           "x₁ mod n  (entero)",      "H(x₁)  (bytes)"),
        ("Hash de mensaje",      "e = H(m)",                "e = H(h_cert‖m)"),
        ("Inverso en firma",     "k⁻¹ mod n",               "ninguno"),
        ("Inverso en verif.",    "s⁻¹ mod n",               "ninguno"),
        ("Mult. EC en verif.",   "u₁·G + u₂·Q  (2 mul)",   "s·Q + w̄·G  (2 mul)"),
        ("Estándar",             "FIPS 186-5",               "ISO/IEC 15946-2"),
        ("Origen",               "EE.UU. (NIST)",            "Corea del Sur"),
    ]
    for r in rows:
        print(f"  {r[0]:<28}  {r[1]:<22}  {r[2]}")
    print()


# ──────────────────────────────────────────────────────────────────────

def main():
    demo_ecdsa()
    demo_ec_kcdsa()
    print_comparison()


if __name__ == "__main__":
    main()
