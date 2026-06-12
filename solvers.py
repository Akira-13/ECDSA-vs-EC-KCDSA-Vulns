from pwn import *
import hashlib

# Deshabilitar el registro excesivo de pwntools para una salida más limpia
context.log_level = 'info'

# Orden de la curva SECP256K1
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# --- Ayudantes Criptográficos ---

def hash_to_int(msg: bytes) -> int:
    """Retorna SHA-256 del mensaje como entero."""
    return int.from_bytes(hashlib.sha256(msg).digest(), 'big')

def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# --- Funciones de Explotación ---

def solve_ecdsa_reuse(host='localhost', port=2001):
    log.info("Iniciando Ataque: Reutilización de Nonce en ECDSA")
    r = remote(host, port)
    
    msg1 = b"hack"
    msg2 = b"the"
    
    # 1. Firmar msg1
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'Hex: ', msg1.hex().encode())
    r.recvuntil(b'Firma (r, s): (')
    r_val, s1_val = map(int, r.recvline().decode().strip().strip(')').split(', '))
    
    # 2. Firmar msg2
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'Hex: ', msg2.hex().encode())
    r.recvuntil(b'Firma (r, s): (')
    _, s2_val = map(int, r.recvline().decode().strip().strip(')').split(', '))
    
    # 3. Momento de las Matemáticas
    e1 = hash_to_int(msg1)
    e2 = hash_to_int(msg2)
    
    # k = (e1 - e2) / (s1 - s2) mod N
    k = ((e1 - e2) * pow(s1_val - s2_val, -1, N)) % N
    
    # d = (s1*k - e1) / r mod N
    d = ((s1_val * k - e1) * pow(r_val, -1, N)) % N
    
    log.success(f"d recuperada: {d}")
    
    # 4. Enviar y obtener flag
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b'd: ', str(d).encode())
    log.info(f"Resultado: {r.recvline().decode().strip()}")
    r.close()

def solve_ecdsa_leak(host='localhost', port=2002):
    log.info("\nIniciando Ataque: Fuga de Nonce en ECDSA")
    r = remote(host, port)
    
    msg = b"planet"
    
    # 1. Firmar mensaje y capturar fuga
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'Hex: ', msg.hex().encode())
    r.recvuntil(b'Firma (r, s): (')
    r_val, s_val = map(int, r.recvline().decode().strip().strip(')').split(', '))
    r.recvuntil(b'usado: ')
    k = int(r.recvline().decode().strip())
    
    # 2. Momento de las Matemáticas
    e = hash_to_int(msg)
    
    # d = (s*k - e) / r mod N
    d = ((s_val * k - e) * pow(r_val, -1, N)) % N
    
    log.success(f"d recuperada: {d}")
    
    # 3. Enviar y obtener flag
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b'd: ', str(d).encode())
    log.info(f"Resultado: {r.recvline().decode().strip()}")
    r.close()

def solve_kcdsa_reuse(host='localhost', port=2003):
    log.info("\nIniciando Ataque: Reutilización de Nonce en EC-KCDSA")
    r = remote(host, port)
    
    msg1 = b"gimme"
    msg2 = b"flag"
    
    # 1. Obtener h_cert
    r.sendlineafter(b'> ', b'1')
    r.recvuntil(b'h_cert (hex): ')
    h_cert = bytes.fromhex(r.recvline().decode().strip())
    
    # 2. Firmar msg1
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'Hex: ', msg1.hex().encode())
    r.recvuntil(b'Firma r (hex): ')
    r_hex = bytes.fromhex(r.recvline().decode().strip())
    r.recvuntil(b'Firma s (int): ')
    s1 = int(r.recvline().decode().strip())
    
    # 3. Firmar msg2
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'Hex: ', msg2.hex().encode())
    r.recvuntil(b'Firma r (hex): ')
    r.recvline() # Saltar r, es el mismo
    r.recvuntil(b'Firma s (int): ')
    s2 = int(r.recvline().decode().strip())
    
    # 4. Momento de las Matemáticas
    e1 = sha256_bytes(h_cert + msg1)
    e2 = sha256_bytes(h_cert + msg2)
    
    w_bar1 = int.from_bytes(xor_bytes(r_hex, e1), "big")
    if w_bar1 >= N: w_bar1 -= N
        
    w_bar2 = int.from_bytes(xor_bytes(r_hex, e2), "big")
    if w_bar2 >= N: w_bar2 -= N
    
    # d = (s1 - s2) / (w_bar2 - w_bar1) mod N
    d = ((s1 - s2) * pow(w_bar2 - w_bar1, -1, N)) % N
    
    log.success(f"d recuperada: {d}")
    
    # 5. Enviar y obtener flag
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b'd: ', str(d).encode())
    log.info(f"Resultado: {r.recvline().decode().strip()}")
    r.close()

def solve_kcdsa_leak(host='localhost', port=2004):
    log.info("\nIniciando Ataque: Fuga de Nonce en EC-KCDSA")
    r = remote(host, port)
    
    msg = b"hello"
    
    # 1. Obtener h_cert
    r.sendlineafter(b'> ', b'1')
    r.recvuntil(b'h_cert (hex): ')
    h_cert = bytes.fromhex(r.recvline().decode().strip())
    
    # 2. Firmar mensaje y capturar fuga
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'Hex: ', msg.hex().encode())
    r.recvuntil(b'Firma r (hex): ')
    r_hex = bytes.fromhex(r.recvline().decode().strip())
    r.recvuntil(b'Firma s (int): ')
    s_val = int(r.recvline().decode().strip())
    r.recvuntil(b'usado: ')
    k = int(r.recvline().decode().strip())
    
    # 3. Momento de las Matemáticas
    e = sha256_bytes(h_cert + msg)
    w_bar = int.from_bytes(xor_bytes(r_hex, e), "big")
    if w_bar >= N: w_bar -= N
        
    # d = s / (k - w_bar) mod N
    d = (s_val * pow(k - w_bar, -1, N)) % N
    
    log.success(f"d recuperada: {d}")
    
    # 4. Enviar y obtener flag
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b'd: ', str(d).encode())
    log.info(f"Resultado: {r.recvline().decode().strip()}")
    r.close()

if __name__ == '__main__':
    solve_ecdsa_reuse()
    solve_ecdsa_leak()
    solve_kcdsa_reuse()
    solve_kcdsa_leak()