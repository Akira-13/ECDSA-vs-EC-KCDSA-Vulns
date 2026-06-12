# Laboratorio CTF: Vulnerabilidades en Firmas de Curvas Elípticas

Este repositorio contiene un entorno de laboratorio estilo CTF (Capture The Flag) diseñado para demostrar vulnerabilidades críticas en la implementación de algoritmos de firma digital basados en curvas elípticas, específicamente **ECDSA** y **EC-KCDSA** sobre la curva `secp256k1`.

El objetivo de estos retos es explotar la mala gestión del número efímero (o *nonce*) $k$, demostrando cómo su reutilización o filtración conduce a la recuperación total de la clave privada $d$.


## Configuración y Despliegue (Setup)

### Requisitos Previos

* [Docker](https://docs.docker.com/get-docker/) y [Docker Compose](https://docs.docker.com/compose/install/)
* Python 3.8+ (para ejecutar el solver)
* Librería `pwntools` (instalable vía `pip install pwntools`)

### Levantar los Oráculos (Servidores)

El laboratorio utiliza contenedores aislados con `socat` para simular conexiones de red reales. Para construir y levantar todos los retos en segundo plano, ejecuta en la raíz del proyecto:

```bash
docker-compose up --build -d

```

Esto expondrá los siguientes puertos en tu máquina local (`localhost`):

* **Puerto 2001:** ECDSA - Reutilización de Nonce
* **Puerto 2002:** ECDSA - Filtración de Nonce
* **Puerto 2003:** EC-KCDSA - Reutilización de Nonce
* **Puerto 2004:** EC-KCDSA - Filtración de Nonce

Puedes interactuar manualmente con cualquiera de los retos usando `netcat`:

```bash
nc localhost 2001

```

### Ejecutar el Exploit Automático

El archivo `solvers.py` contiene los scripts para solucionar los cuatro desafíos. Para ejecutar el ataque completo y capturar las *flags*:

```bash
python3 exploit.py

```

## 🦠 Explicación de las Vulnerabilidades

En los algoritmos de firma de curvas elípticas, el valor $k$ (nonce o secreto efímero) debe ser un número aleatorio, impredecible y **estrictamente de un solo uso**. Si estas reglas se rompen, la seguridad de todo el esquema colapsa. El orden del subgrupo de la curva se denota como $n$, y todas las operaciones se realizan en módulo $n$.

### 1. ECDSA: Reutilización de Nonce ($k$)

Si se firman dos mensajes diferentes ($m_1$ y $m_2$) usando el mismo valor de $k$, el punto efímero $R = k \cdot G$ será el mismo, por lo que la componente $r$ de la firma será idéntica en ambos casos.

Las ecuaciones para las dos firmas ($s_1$ y $s_2$) son:


$$s_1 = k^{-1}(e_1 + d \cdot r) \pmod n$$

$$s_2 = k^{-1}(e_2 + d \cdot r) \pmod n$$

Restando ambas ecuaciones, la clave privada $d$ se anula, permitiéndonos despejar el valor del nonce $k$:


$$k = (e_1 - e_2) \cdot (s_1 - s_2)^{-1} \pmod n$$

Una vez obtenido $k$, podemos despejar la clave privada $d$ de cualquiera de las firmas originales:


$$d = (s_1 \cdot k - e_1) \cdot r^{-1} \pmod n$$

### 2. ECDSA: Filtración de Nonce ($k$)

Si por un error de implementación (logs, fallos de canal lateral, generadores de números pseudoaleatorios predecibles) el atacante conoce el valor de $k$ utilizado para una firma específica $(r, s)$, el ataque es trivial.

Tomando la ecuación base y multiplicando por $k$, obtenemos:


$$s \cdot k = e + d \cdot r \pmod n$$

Simplemente despejamos la clave privada $d$:


$$d = (s \cdot k - e) \cdot r^{-1} \pmod n$$

### 3. EC-KCDSA: Reutilización de Nonce ($k$)

A diferencia de ECDSA, en EC-KCDSA la ecuación de la firma para la componente $s$ se define como:


$$s = d \cdot (k - \bar{w}) \pmod n$$


Donde $\bar{w}$ deriva del hash del mensaje y de la componente $r$.

Si se reutiliza $k$, el valor $r$ será constante, pero los valores $\bar{w}_1$ y $\bar{w}_2$ serán diferentes. Tenemos dos ecuaciones:


$$s_1 = d \cdot (k - \bar{w}_1) \pmod n$$

$$s_2 = d \cdot (k - \bar{w}_2) \pmod n$$

Al restar ambas ecuaciones, el nonce $k$ desaparece por completo, permitiendo recuperar la clave privada **directamente**, sin necesidad de calcular $k$ en el proceso:


$$s_1 - s_2 = d \cdot (\bar{w}_2 - \bar{w}_1) \pmod n$$

$$d = (s_1 - s_2) \cdot (\bar{w}_2 - \bar{w}_1)^{-1} \pmod n$$

### 4. EC-KCDSA: Filtración de Nonce ($k$)

Si el atacante logra comprometer el valor de $k$ utilizado para una firma $(r, s)$ de un mensaje conocido, la recuperación de la clave privada es directa. A partir de la ecuación base:


$$s = d \cdot (k - \bar{w}) \pmod n$$

Despejamos $d$:


$$d = s \cdot (k - \bar{w})^{-1} \pmod n$$


> Proyecto con fines educativos.
