import sys
from ec import SECP256K1
import ec_kcdsa

sys.stdout.reconfigure(line_buffering=True)

FLAG = "FLAG{papu_de_que_trabajo_hablan}"
curva = SECP256K1
d, Q, h_cert = ec_kcdsa.keygen(curva)
FIXED_K = 0x9999999999999999999999999999999999999999999999999999999999999999

def main():
    print("=== ORÁCULO EC-KCDSA: REUTILIZACIÓN DE NONCE ===")
    while True:
        print("\n1. Obtener Clave Pública y Hash Cert\n2. Firmar Mensaje\n3. Entregar Clave Privada (Flag)\n4. Salir")
        try:
            opcion = input("> ").strip()
            if opcion == "1":
                print(f"[+] Clave Pública Q: {Q}")
                print(f"[+] h_cert (hex): {h_cert.hex()}")
            elif opcion == "2":
                msg_hex = input("Introduce mensaje en Hex: ").strip()
                msg = bytes.fromhex(msg_hex)
                
                n = curva.n
                kG = curva.mul(FIXED_K, curva.G)
                r = ec_kcdsa._sha256(ec_kcdsa._x_a_bytes(kG[0]))
                e = ec_kcdsa._sha256(h_cert + msg)
                w_bar = int.from_bytes(ec_kcdsa._xor_bytes(r, e), "big")
                if w_bar >= n: w_bar -= n
                s = d * (FIXED_K - w_bar) % n
                
                print(f"[+] Firma r (hex): {r.hex()}")
                print(f"[+] Firma s (int): {s}")
            elif choice := opcion == "3":
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
