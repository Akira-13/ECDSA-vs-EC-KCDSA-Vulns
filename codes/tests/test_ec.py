"""
Pruebas de aritmética de curvas elípticas (src/ec.py).

Cubre:
  - Integridad de la curva (generador en la curva, discriminante ≠ 0)
  - Identidad / elemento neutro
  - Inverso (P + (−P) = ∞)
  - Conmutatividad y asociatividad
  - Correctitud de la multiplicación escalar (vectores de prueba conocidos)
  - Orden: n·G = ∞
  - Los resultados siempre pertenecen a la curva
"""

import secrets
import pytest
from src.ec import SECP256K1, P256, Point


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(params=[SECP256K1, P256], ids=["secp256k1", "P-256"])
def curva(request):
    return request.param


# ── Integridad de la curva ────────────────────────────────────────────

def test_generador_en_curva(curva):
    assert curva.is_on_curve(curva.G), f"El generador G debe estar en {curva.name}"


def test_infinito_en_curva(curva):
    assert curva.is_on_curve(None)


def test_discriminante_no_nulo():
    """Δ = −16(4a³ + 27b²) ≠ 0 mod p garantiza que la curva es no singular."""
    for c in (SECP256K1, P256):
        delta = (-16 * (4 * pow(c.a, 3, c.p) + 27 * pow(c.b, 2, c.p))) % c.p
        assert delta != 0, f"{c.name}: el discriminante debe ser no nulo"


# ── Identidad (elemento neutro) ───────────────────────────────────────

def test_sumar_neutro_derecha(curva):
    assert curva.add(curva.G, None) == curva.G


def test_sumar_neutro_izquierda(curva):
    assert curva.add(None, curva.G) == curva.G


def test_infinito_mas_infinito(curva):
    assert curva.add(None, None) is None


# ── Inverso ───────────────────────────────────────────────────────────

def test_inverso_suma_es_infinito(curva):
    neg_G = curva.neg(curva.G)
    assert curva.add(curva.G, neg_G) is None


def test_doble_negativo_es_identidad(curva):
    assert curva.neg(curva.neg(curva.G)) == curva.G


def test_negativo_infinito_es_infinito(curva):
    assert curva.neg(None) is None


# ── Doblado ───────────────────────────────────────────────────────────

def test_resultado_doblado_en_curva(curva):
    dos_G = curva.add(curva.G, curva.G)
    assert curva.is_on_curve(dos_G)


def test_mul_2_igual_a_sumar(curva):
    """2·G por mul debe coincidir con G+G por add."""
    assert curva.mul(2, curva.G) == curva.add(curva.G, curva.G)


# ── Vectores de prueba conocidos ──────────────────────────────────────

def test_2G_secp256k1_vector_conocido():
    """
    Valor conocido: 2·G para secp256k1, verificado por evaluación directa
    de la fórmula de doblado.  La coordenada x coincide con la referencia
    ampliamente citada; la coordenada y es la solución consistente con la
    fórmula tangente y la paridad de Gy.
    """
    esperado = (
        0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
        0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
    )
    dos_G = SECP256K1.mul(2, SECP256K1.G)
    assert SECP256K1.is_on_curve(dos_G), "2G debe estar en la curva"
    assert dos_G == esperado


def test_3G_secp256k1_vector_conocido():
    """Valor conocido: 3·G para secp256k1."""
    esperado = (
        0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,
        0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672,
    )
    assert SECP256K1.mul(3, SECP256K1.G) == esperado


# ── Orden ─────────────────────────────────────────────────────────────

def test_orden_secp256k1():
    """n·G = ∞ para secp256k1 (prueba de correctitud más crítica)."""
    assert SECP256K1.mul(SECP256K1.n, SECP256K1.G) is None


# ── Leyes algebraicas ─────────────────────────────────────────────────

def test_conmutatividad(curva):
    """P + Q = Q + P para puntos arbitrarios."""
    P = curva.mul(5, curva.G)
    Q = curva.mul(7, curva.G)
    assert curva.add(P, Q) == curva.add(Q, P)


def test_asociatividad(curva):
    """(P + Q) + R = P + (Q + R)."""
    P = curva.mul(3, curva.G)
    Q = curva.mul(5, curva.G)
    R = curva.mul(7, curva.G)
    izq = curva.add(curva.add(P, Q), R)
    der = curva.add(P, curva.add(Q, R))
    assert izq == der


def test_mult_escalar_aditiva_pequena(curva):
    """k·G = G + G + … + G (k veces) para k pequeño."""
    k = 8
    esperado: Point = None
    for _ in range(k):
        esperado = curva.add(esperado, curva.G)
    assert curva.mul(k, curva.G) == esperado


def test_mult_escalar_distributiva(curva):
    """(a + b)·G = a·G + b·G."""
    a, b = 13, 17
    izq = curva.mul(a + b, curva.G)
    der = curva.add(curva.mul(a, curva.G), curva.mul(b, curva.G))
    assert izq == der


def test_mult_escalar_cero(curva):
    assert curva.mul(0, curva.G) is None


def test_mult_escalar_uno(curva):
    assert curva.mul(1, curva.G) == curva.G


def test_mult_escalar_negativo(curva):
    """(−k)·G = −(k·G)."""
    k = 9
    assert curva.mul(-k, curva.G) == curva.neg(curva.mul(k, curva.G))


def test_multiplos_aleatorios_en_curva(curva):
    """Los múltiplos escalares aleatorios siempre deben estar en la curva."""
    for _ in range(8):
        k = secrets.randbelow(curva.n - 1) + 1
        P = curva.mul(k, curva.G)
        assert curva.is_on_curve(P), f"k·G no está en {curva.name} para k={k}"
