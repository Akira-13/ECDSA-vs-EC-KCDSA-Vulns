import sys
import secrets
from ec import SECP256K1
import ecdsa

sys.stdout.reconfigure(line_buffering=True)

FLAG = "FLAG{discipulo_de_jm}"
curva = SECP256K1
d, Q = ecdsa.keygen(curva)

def main():
    print("=== ORÁCULO ECDSA: FILTRACIÓN DE NONCE ===")
    while True:
        print("\n1. Obtener Clave Pública\n2. Firmar Mensaje (Fuga de k)\n3. Entregar Clave Privada (Flag)\n4. Salir")
        try:
            opcion = input("> ").strip()
            if opcion == "1":
                print(f"[+] Clave Pública Q: {Q}")
            elif opcion == "2":
                msg_hex = input("Introduce mensaje en Hex: ").strip()
                msg = bytes.fromhex(msg_hex)
                k = secrets.randbelow(curva.n - 1) + 1
                e = ecdsa._hash_a_entero(msg)
                R = curva.mul(k, curva.G)
                r = R[0] % curva.n
                s = pow(k, -1, curva.n) * (e + d * r) % curva.n
                print(f"[+] Firma (r, s): ({r}, {s})")
                print(f"[*] ¡Fuga! Nonce k usado: {k}")
            elif opcion == "3":
                intento = int(input("Introduce la clave privada d: ").strip(), 0)
                if intento == d:
                    print(f"[+] ¡Correcto! Tu Flag: {FLAG}")
                else:
                    print("[-] Incorrecto.")
            elif opcion == "4":
                break
        except Exception as ex:
            print(f"[-] Error: {ex}")
            break

if __name__ == "__main__":
    main()
