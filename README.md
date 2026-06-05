# ECDSA vs EC-KCDSA

Implementación **from scratch** en Python de dos algoritmos de firma digital basados en curvas elípticas, con benchmark de rendimiento y análisis de seguridad comparativo.

| Algoritmo | Estándar | Origen |
|---|---|---|
| ECDSA | FIPS 186-5 / ANSI X9.62 | EE.UU. (NIST) |
| EC-KCDSA | ISO/IEC 15946-2 / TTAK.KO-12.0015 | Corea del Sur |

---

## Requisitos

- Python 3.8 o superior (se usa `pow(a, -1, m)` para inversas modulares)
- pip

Dependencias del proyecto:

```
pytest >= 7.0
matplotlib >= 3.5   # opcional, solo para gráficas del benchmark
```

---

## Instalación

```bash
git clone <url-del-repositorio>
cd ECDSA-vs-EC-KCDSA/codes

pip install pytest
# Opcional, para gráficas:
pip install matplotlib
```

No se requiere ninguna librería criptográfica externa. Toda la aritmética de curvas elípticas está implementada desde cero en `codes/src/ec.py`.

---

## Estructura del proyecto

```
ECDSA-vs-EC-KCDSA/
├── codes/
│   ├── src/
│   │   ├── ec.py          # Aritmética de curvas elípticas (secp256k1, P-256)
│   │   ├── ecdsa.py       # Implementación de ECDSA
│   │   └── ec_kcdsa.py    # Implementación de EC-KCDSA
│   ├── tests/
│   │   ├── test_ec.py         # Tests de aritmética de curvas
│   │   ├── test_ecdsa.py      # Tests de ECDSA
│   │   └── test_ec_kcdsa.py   # Tests de EC-KCDSA
│   ├── main.py            # Demo interactivo de ambos algoritmos
│   ├── benchmark.py       # Benchmark de rendimiento con N variable
│   ├── conftest.py        # Configuración de pytest
│   └── requirements.txt
└── docs/
    └── benchmark_results.png  # Gráfica generada por benchmark.py
```

---

## Ejecutar el demo

```bash
cd codes/
python main.py
```

Muestra generación de claves, firma, verificación y tabla comparativa de propiedades para ambos algoritmos sobre secp256k1.

---

## Ejecutar los tests

Desde el directorio `codes/`:

```bash
# Todos los tests
pytest tests/ -v

# Solo tests de aritmética de curvas
pytest tests/test_ec.py -v

# Solo tests de ECDSA
pytest tests/test_ecdsa.py -v

# Solo tests de EC-KCDSA
pytest tests/test_ec_kcdsa.py -v

# Un test específico
pytest tests/test_ec.py::test_orden_secp256k1 -v
```

Salida esperada:

```
114 passed in ~1.5s
```

---

## Ejecutar el benchmark

```bash
cd codes/
python benchmark.py
```

Opciones disponibles:

```bash
# Personalizar repeticiones y tamaños de mensaje
python benchmark.py --reps 30 --sizes 64,1024,65536

# Sin gráfica
python benchmark.py --no-plot

# Guardar gráfica en ruta personalizada
python benchmark.py --plot-out resultados.png

# Ver todas las opciones
python benchmark.py --help
```

El benchmark mide keygen, sign y verify para mensajes de tamaño `[64, 256, 1024, 4096, 16384, 65536]` bytes, con 20 repeticiones y 3 de calentamiento por defecto. La gráfica se guarda como `benchmark_results.png`.

---

## Curvas soportadas

| Curva | p (bits) | Uso |
|---|---|---|
| `secp256k1` | 256 | Bitcoin, Ethereum |
| `P-256` (secp256r1) | 256 | TLS 1.3, FIPS 186-5 |

Los tests corren sobre ambas curvas automáticamente via fixtures parametrizadas de pytest.
