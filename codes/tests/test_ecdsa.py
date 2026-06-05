"""
Pruebas de ECDSA (src/ecdsa.py).

Cubre:
  - Validez de la generación de claves
  - Ciclo completo firma / verificación
  - Rechazo ante mensaje alterado, firma alterada, clave incorrecta
  - Casos borde: mensaje vacío, mensaje grande, (r, s) fuera de rango
  - Curvas secp256k1 y P-256
"""

import os
import pytest
from src.ec import SECP256K1, P256
from src import ecdsa


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(params=[SECP256K1, P256], ids=["secp256k1", "P-256"])
def curva(request):
    return request.param


# ── Generación de claves ──────────────────────────────────────────────

def test_clave_privada_en_rango(curva):
    d, _ = ecdsa.keygen(curva)
    assert 1 <= d <= curva.n - 1


def test_clave_publica_en_curva(curva):
    d, Q = ecdsa.keygen(curva)
    assert curva.is_on_curve(Q)


def test_clave_publica_igual_a_d_por_G(curva):
    d, Q = ecdsa.keygen(curva)
    assert Q == curva.mul(d, curva.G)


# ── Ciclo firma / verificación ────────────────────────────────────────

def test_ciclo_basico(curva):
    d, Q = ecdsa.keygen(curva)
    msg = b"Hola mundo - ECDSA"
    sig = ecdsa.sign(msg, d, curva)
    assert ecdsa.verify(msg, sig, Q, curva)


def test_ciclo_mensaje_vacio(curva):
    d, Q = ecdsa.keygen(curva)
    sig = ecdsa.sign(b"", d, curva)
    assert ecdsa.verify(b"", sig, Q, curva)


def test_ciclo_un_solo_byte(curva):
    d, Q = ecdsa.keygen(curva)
    sig = ecdsa.sign(b"\x00", d, curva)
    assert ecdsa.verify(b"\x00", sig, Q, curva)


def test_ciclo_mensaje_grande(curva):
    d, Q = ecdsa.keygen(curva)
    msg = os.urandom(65_536)
    sig = ecdsa.sign(msg, d, curva)
    assert ecdsa.verify(msg, sig, Q, curva)


def test_componentes_firma_en_rango(curva):
    d, _ = ecdsa.keygen(curva)
    r, s = ecdsa.sign(b"test", d, curva)
    assert 1 <= r <= curva.n - 1
    assert 1 <= s <= curva.n - 1


def test_firmas_no_deterministas(curva):
    """Dos llamadas con el mismo (mensaje, clave) deben producir (r, s) distintos."""
    d, _ = ecdsa.keygen(curva)
    msg = b"mismo mensaje"
    sig1 = ecdsa.sign(msg, d, curva)
    sig2 = ecdsa.sign(msg, d, curva)
    # Con probabilidad abrumadora los nonces aleatorios difieren.
    assert sig1 != sig2


# ── Pruebas de rechazo ────────────────────────────────────────────────

def test_rechazar_mensaje_alterado(curva):
    d, Q = ecdsa.keygen(curva)
    msg = b"mensaje original"
    sig = ecdsa.sign(msg, d, curva)
    assert not ecdsa.verify(b"mensaje alterado", sig, Q, curva)


def test_rechazar_bit_r_modificado(curva):
    d, Q = ecdsa.keygen(curva)
    msg = b"test"
    r, s = ecdsa.sign(msg, d, curva)
    assert not ecdsa.verify(msg, (r ^ 1, s), Q, curva)


def test_rechazar_bit_s_modificado(curva):
    d, Q = ecdsa.keygen(curva)
    msg = b"test"
    r, s = ecdsa.sign(msg, d, curva)
    assert not ecdsa.verify(msg, (r, s ^ 1), Q, curva)


def test_rechazar_clave_publica_incorrecta(curva):
    d, Q = ecdsa.keygen(curva)
    _, Q2 = ecdsa.keygen(curva)
    msg = b"mensaje"
    sig = ecdsa.sign(msg, d, curva)
    assert not ecdsa.verify(msg, sig, Q2, curva)


def test_rechazar_r_igual_a_cero(curva):
    d, Q = ecdsa.keygen(curva)
    r, s = ecdsa.sign(b"test", d, curva)
    assert not ecdsa.verify(b"test", (0, s), Q, curva)


def test_rechazar_s_igual_a_cero(curva):
    d, Q = ecdsa.keygen(curva)
    r, s = ecdsa.sign(b"test", d, curva)
    assert not ecdsa.verify(b"test", (r, 0), Q, curva)


def test_rechazar_r_igual_a_n(curva):
    d, Q = ecdsa.keygen(curva)
    r, s = ecdsa.sign(b"test", d, curva)
    assert not ecdsa.verify(b"test", (curva.n, s), Q, curva)


def test_rechazar_s_igual_a_n(curva):
    d, Q = ecdsa.keygen(curva)
    r, s = ecdsa.sign(b"test", d, curva)
    assert not ecdsa.verify(b"test", (r, curva.n), Q, curva)


def test_rechazo_entre_curvas():
    """Una firma producida en secp256k1 no debe verificarse en P-256."""
    d, _ = ecdsa.keygen(SECP256K1)
    _, Q_p256 = ecdsa.keygen(P256)
    msg = b"prueba entre curvas"
    sig = ecdsa.sign(msg, d, SECP256K1)
    assert not ecdsa.verify(msg, sig, Q_p256, P256)
