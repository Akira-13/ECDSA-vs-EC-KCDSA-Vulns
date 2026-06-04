"""
Pruebas de EC-KCDSA (src/ec_kcdsa.py).

Cubre:
  - Validez de la generación de claves (Q = d⁻¹·G)
  - Ciclo completo firma / verificación
  - Rechazo ante mensaje alterado, r, s, clave incorrecta, h_cert incorrecto
  - Casos borde: mensaje vacío, mensaje grande, s fuera de rango
  - Curvas secp256k1 y P-256
"""

import os
import pytest
from src.ec import SECP256K1, P256
from src import ec_kcdsa


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(params=[SECP256K1, P256], ids=["secp256k1", "P-256"])
def curva(request):
    return request.param


# ── Generación de claves ──────────────────────────────────────────────

def test_clave_privada_en_rango(curva):
    d, _, _ = ec_kcdsa.keygen(curva)
    assert 1 <= d <= curva.n - 1


def test_clave_publica_en_curva(curva):
    _, Q, _ = ec_kcdsa.keygen(curva)
    assert curva.is_on_curve(Q)


def test_clave_publica_es_d_inv_por_G(curva):
    """Propiedad definitoria de EC-KCDSA: Q = d⁻¹·G."""
    d, Q, _ = ec_kcdsa.keygen(curva)
    d_inv = pow(d, -1, curva.n)
    assert Q == curva.mul(d_inv, curva.G)


def test_longitud_h_cert(curva):
    _, _, h_cert = ec_kcdsa.keygen(curva)
    assert len(h_cert) == 32  # SHA-256


# ── Ciclo firma / verificación ────────────────────────────────────────

def test_ciclo_basico(curva):
    d, Q, h_cert = ec_kcdsa.keygen(curva)
    msg = b"Hola mundo - EC-KCDSA"
    sig = ec_kcdsa.sign(msg, d, h_cert, curva)
    assert ec_kcdsa.verify(msg, sig, Q, h_cert, curva)


def test_ciclo_mensaje_vacio(curva):
    d, Q, h_cert = ec_kcdsa.keygen(curva)
    sig = ec_kcdsa.sign(b"", d, h_cert, curva)
    assert ec_kcdsa.verify(b"", sig, Q, h_cert, curva)


def test_ciclo_un_solo_byte(curva):
    d, Q, h_cert = ec_kcdsa.keygen(curva)
    sig = ec_kcdsa.sign(b"\xff", d, h_cert, curva)
    assert ec_kcdsa.verify(b"\xff", sig, Q, h_cert, curva)


def test_ciclo_mensaje_grande(curva):
    d, Q, h_cert = ec_kcdsa.keygen(curva)
    msg = os.urandom(65_536)
    sig = ec_kcdsa.sign(msg, d, h_cert, curva)
    assert ec_kcdsa.verify(msg, sig, Q, h_cert, curva)


def test_r_es_bytes_de_longitud_correcta(curva):
    d, _, h_cert = ec_kcdsa.keygen(curva)
    r, _ = ec_kcdsa.sign(b"test", d, h_cert, curva)
    assert isinstance(r, bytes)
    assert len(r) == 32


def test_s_en_rango(curva):
    d, _, h_cert = ec_kcdsa.keygen(curva)
    _, s = ec_kcdsa.sign(b"test", d, h_cert, curva)
    assert 1 <= s <= curva.n - 1


def test_firmas_no_deterministas(curva):
    d, _, h_cert = ec_kcdsa.keygen(curva)
    msg = b"mismo mensaje"
    sig1 = ec_kcdsa.sign(msg, d, h_cert, curva)
    sig2 = ec_kcdsa.sign(msg, d, h_cert, curva)
    assert sig1 != sig2


# ── Pruebas de rechazo ────────────────────────────────────────────────

def test_rechazar_mensaje_alterado(curva):
    d, Q, h_cert = ec_kcdsa.keygen(curva)
    msg = b"mensaje original"
    sig = ec_kcdsa.sign(msg, d, h_cert, curva)
    assert not ec_kcdsa.verify(b"mensaje alterado", sig, Q, h_cert, curva)


def test_rechazar_r_alterado(curva):
    d, Q, h_cert = ec_kcdsa.keygen(curva)
    msg = b"test"
    r, s = ec_kcdsa.sign(msg, d, h_cert, curva)
    bad_r = bytes([r[0] ^ 0xFF]) + r[1:]
    assert not ec_kcdsa.verify(msg, (bad_r, s), Q, h_cert, curva)


def test_rechazar_bit_s_modificado(curva):
    d, Q, h_cert = ec_kcdsa.keygen(curva)
    msg = b"test"
    r, s = ec_kcdsa.sign(msg, d, h_cert, curva)
    assert not ec_kcdsa.verify(msg, (r, s ^ 1), Q, h_cert, curva)


def test_rechazar_clave_publica_incorrecta(curva):
    d, Q, h_cert = ec_kcdsa.keygen(curva)
    _, Q2, _ = ec_kcdsa.keygen(curva)
    msg = b"mensaje"
    sig = ec_kcdsa.sign(msg, d, h_cert, curva)
    assert not ec_kcdsa.verify(msg, sig, Q2, h_cert, curva)


def test_rechazar_h_cert_incorrecto(curva):
    """Una firma generada con un h_cert no debe verificarse con otro distinto."""
    d, Q, h_cert = ec_kcdsa.keygen(curva)
    _, _, h_cert2 = ec_kcdsa.keygen(curva)
    msg = b"mensaje"
    sig = ec_kcdsa.sign(msg, d, h_cert, curva)
    assert not ec_kcdsa.verify(msg, sig, Q, h_cert2, curva)


def test_rechazar_s_igual_a_cero(curva):
    d, Q, h_cert = ec_kcdsa.keygen(curva)
    r, s = ec_kcdsa.sign(b"test", d, h_cert, curva)
    assert not ec_kcdsa.verify(b"test", (r, 0), Q, h_cert, curva)


def test_rechazar_s_igual_a_n(curva):
    d, Q, h_cert = ec_kcdsa.keygen(curva)
    r, _ = ec_kcdsa.sign(b"test", d, h_cert, curva)
    assert not ec_kcdsa.verify(b"test", (r, curva.n), Q, h_cert, curva)


def test_rechazar_r_demasiado_largo(curva):
    """r con más de l_H bytes debe ser rechazado."""
    d, Q, h_cert = ec_kcdsa.keygen(curva)
    r, s = ec_kcdsa.sign(b"test", d, h_cert, curva)
    bad_r = r + b"\x00"   # 33 bytes — supera l_H = 32
    assert not ec_kcdsa.verify(b"test", (bad_r, s), Q, h_cert, curva)


def test_rechazo_entre_curvas():
    """Una firma de secp256k1 no debe verificarse en P-256."""
    d, _, h_cert = ec_kcdsa.keygen(SECP256K1)
    _, Q2, h_cert2 = ec_kcdsa.keygen(P256)
    msg = b"prueba entre curvas"
    sig = ec_kcdsa.sign(msg, d, h_cert, SECP256K1)
    assert not ec_kcdsa.verify(msg, sig, Q2, h_cert2, P256)
