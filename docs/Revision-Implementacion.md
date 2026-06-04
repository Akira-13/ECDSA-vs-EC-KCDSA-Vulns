# Revisión de la implementación vs. reporte teórico

Verificación de que el código en `codes/src/` implementa fielmente los algoritmos descritos en `Reporte-Seguridad-ECC.md`.

---

## 1. `src/ec.py` — Aritmética de curvas elípticas

### Definición de la curva y punto en el infinito (Ec. 11 y 12)

| Reporte | Implementación | Veredicto |
|---|---|---|
| E: y² = x³ + ax + b, Δ ≠ 0 | Ecuación `y² = x³ + ax + b`; `None` representa ∞ | ✓ |
| Δ = −16(4a³ + 27b²) ≠ 0 | `(-16*(4*a³ + 27*b²)) % p != 0` (verificado en tests) | ✓ |

### Suma de puntos P ≠ Q (Ec. 13)

| Reporte | Implementación | Veredicto |
|---|---|---|
| λ = (y₂−y₁)/(x₂−x₁) | `lam = (y2-y1)*pow(x2-x1,-1,p) % p` | ✓ |
| x₃ = λ²−x₁−x₂ | `x3 = (lam*lam - x1 - x2) % p` | ✓ |
| y₃ = λ(x₁−x₃)−y₁ | `y3 = (lam*(x1-x3) - y1) % p` | ✓ |

### Doblado de punto P = Q (Ec. 14)

| Reporte | Implementación | Veredicto |
|---|---|---|
| λ = (3x₁²+a)/(2y₁) | `lam = (3*x1*x1 + self.a)*pow(2*y1,-1,p) % p` | ✓ |
| x₃ = λ²−**2**x₁ | `(lam*lam - x1 - x2) % p` con x1=x2 → λ²−2x₁ | ✓ |
| y₃ = λ(x₁−x₃)−y₁ | `y3 = (lam*(x1-x3) - y1) % p` | ✓ |

### Propiedades del grupo abeliano (Sección 2.3.2.2)

| Propiedad | Implementación | Veredicto |
|---|---|---|
| P + ∞ = P, ∞ + P = P | `if P is None: return Q` / `if Q is None: return P` | ✓ |
| −P = (x, −y mod p) | `(P[0], (-P[1]) % self.p)` | ✓ |
| −∞ = ∞ | `if P is None: return None` en `neg()` | ✓ |
| P + (−P) = ∞ | `if x1==x2 and y1!=y2: return None` | ✓ |

---

## 2. `src/ecdsa.py` — Algoritmos 1.10 y 1.11

### Generación de firma (Algoritmo 1.10)

| Paso del reporte | Código | Veredicto |
|---|---|---|
| 1. k ←R [1, n−1] | `secrets.randbelow(n-1) + 1` | ✓ |
| 2. kP = (x₁, y₁) | `R = curva.mul(k, curva.G); x1, _ = R` | ✓ |
| 3. r = x₁ mod n; si r=0 reintentar | `r = x1 % n; if r == 0: continue` | ✓ |
| 4. e = H(m) | `e = _hash_a_entero(mensaje)` (SHA-256 big-endian) | ✓ |
| 5. s = k⁻¹(e+dr) mod n; si s=0 reintentar | `s = pow(k,-1,n)*(e+d*r)%n; if s==0: continue` | ✓ |
| 6. devolver (r, s) | `return r, s` | ✓ |

> **Nota:** El reporte calcula `e` en el paso 4 dentro del bucle de reintento. Como `e` no depende de `k`, calcularlo antes del bucle (como hace el código) es matemáticamente equivalente y más eficiente.

### Verificación de firma (Algoritmo 1.11)

| Paso del reporte | Código | Veredicto |
|---|---|---|
| 1. Verificar r, s ∈ [1, n−1] | `if not (1<=r<=n-1 and 1<=s<=n-1): return False` | ✓ |
| 2. e = H(m) | `e = _hash_a_entero(mensaje)` | ✓ |
| 3. w = s⁻¹ mod n | `w = pow(s, -1, n)` | ✓ |
| 4. u₁ = ew mod n, u₂ = rw mod n | `u1 = e*w%n; u2 = r*w%n` | ✓ |
| 5. X = u₁P + u₂Q | `X = curva.add(curva.mul(u1, G), curva.mul(u2, Q))` | ✓ |
| 6. Si X = ∞, rechazar | `if X is None: return False` | ✓ |
| 7. r' = x(X) mod n | `x1, _ = X; return x1 % n == r` | ✓ |
| 8. Aceptar si r' = r | (incluido en la línea anterior) | ✓ |

---

## 3. `src/ec_kcdsa.py` — Algoritmos 1.12 y 1.13

### Generación de firma (Algoritmo 1.12)

| Paso del reporte | Código | Veredicto |
|---|---|---|
| 1. k ←R [1, n−1] | `secrets.randbelow(n-1) + 1` | ✓ |
| 2. kP = (x₁, y₁) | `kG = curva.mul(k, curva.G); x1, _ = kG` | ✓ |
| 3. r = H(x₁) | `r = _sha256(_x_a_bytes(x1))` | ✓ |
| 4. e = H(h_cert ‖ m) | `e = _sha256(h_cert + mensaje)` | ✓ |
| 5. w̄ = int(r ⊕ e) | `w_bar = int.from_bytes(_xor_bytes(r, e), "big")` | ✓ |
| 6. Si w̄ ≥ n, entonces w̄ ← w̄−n | `if w_bar >= n: w_bar -= n` | ✓ |
| 7. s = d(k−w̄) mod n; si s=0 reintentar | `s = d*(k-w_bar)%n; if s==0: continue` | ✓ |
| 8. devolver (r, s) | `return r, s` | ✓ |

### Verificación de firma (Algoritmo 1.13)

| Paso del reporte | Código | Veredicto |
|---|---|---|
| 1. \|r\| ≤ l_H bytes, s ∈ [1, n−1] | `len(r) > _L_H → False`; `1 <= s <= n-1` | ✓ |
| 2. e = H(h_cert ‖ m) | `e = _sha256(h_cert + mensaje)` | ✓ |
| 3. w̄ = int(r ⊕ e) | `w_bar = int.from_bytes(_xor_bytes(r, e), "big")` | ✓ |
| 4. Si w̄ ≥ n, entonces w̄ ← w̄−n | `if w_bar >= n: w_bar -= n` | ✓ |
| 5. X = sQ + w̄P | `X = curva.add(curva.mul(s, Q), curva.mul(w_bar, G))` | ✓ |
| 6. v = H(x(X)) | `x1, _ = X; v = _sha256(_x_a_bytes(x1))` | ✓ |
| 7. Aceptar si v = r | `return v == r` | ✓ |

### Propiedad definitoria de la clave pública

| Algoritmo | Relación | Código | Veredicto |
|---|---|---|---|
| ECDSA (Alg. 1.7) | Q = d · P | `curva.mul(d, curva.G)` | ✓ |
| EC-KCDSA (Alg. 1.12) | Q = d⁻¹ · P | `curva.mul(pow(d,-1,n), curva.G)` | ✓ |

---

## 4. Cobertura de tests vs. análisis de seguridad (Sección 3)

### Sección 3.2 — Verificación de r y s

| Vulnerabilidad del reporte | Test que la cubre |
|---|---|
| **ECDSA §3.2.1:** r = 0 genera firma trivial | `test_rechazar_r_igual_a_cero` |
| **ECDSA §3.2.1:** s fuera de [1, n−1] | `test_rechazar_s_igual_a_cero`, `test_rechazar_s_igual_a_n` |
| **ECDSA §3.2.1:** r fuera de [1, n−1] | `test_rechazar_r_igual_a_n` |
| **EC-KCDSA §3.2.2:** s fuera de [1, n−1] | `test_rechazar_s_igual_a_cero`, `test_rechazar_s_igual_a_n` |
| **EC-KCDSA §3.2.2:** \|r\| > l_H permite falsificación | `test_rechazar_r_demasiado_largo` |

### Sección 3.3 — Secreto k

| Vulnerabilidad del reporte | Test que la cubre |
|---|---|
| **ECDSA §3.3.1:** k no debe reutilizarse entre firmas | `test_firmas_no_deterministas` (ECDSA) |
| **EC-KCDSA §3.3.2:** k no debe reutilizarse entre firmas | `test_firmas_no_deterministas` (EC-KCDSA) |

### Pruebas adicionales de robustez

| Escenario | Test que lo cubre |
|---|---|
| Mensaje alterado post-firma | `test_rechazar_mensaje_alterado` |
| Componente r de la firma alterada | `test_rechazar_bit_r_modificado` / `test_rechazar_r_alterado` |
| Componente s de la firma alterada | `test_rechazar_bit_s_modificado` |
| Clave pública incorrecta | `test_rechazar_clave_publica_incorrecta` |
| h_cert incorrecto (EC-KCDSA) | `test_rechazar_h_cert_incorrecto` |
| Firma generada en secp256k1 verificada en P-256 | `test_rechazo_entre_curvas` |

---

## 5. Conclusión

La implementación es fiel al 100% a los algoritmos del reporte. Todos los pasos de los Algoritmos 1.10, 1.11, 1.12 y 1.13 están correctamente codificados, y los tests cubren las vulnerabilidades identificadas en la Sección 3 del análisis de seguridad.

Las dos simplificaciones respecto a una PKI real son intencionadas:

1. `h_cert = SHA256(Qx ‖ Qy)` — sustituto mínimo del hash de certificado real.
2. Multiplicación escalar en tiempo variable — documentado en `ec.py` como uso exclusivamente académico.
