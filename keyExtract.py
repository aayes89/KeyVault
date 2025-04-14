from Cryptodome.PublicKey import RSA
import binascii
import os
import base64

# Exponente público estándar para RSA
DEFAULT_E = 65537  # 0x010001 o AQAB, se puede usar 3 pero no está estandarizado. (explicación larga)

# Mapeo de claves/certificados en el KeyVault
# Los offsets y tamaños son aproximados y pueden necesitar ajustes según el KV
# Hardcodee los offset según las lecturas realizadas usando la función: 
# Advance Key Vault Viewer de "360 Flash Dump Tool 0.95"
KEY_VAULT_KEYS = {
    "KEY_0x33": {"offset": 0x0298, "size": 0x1D0, "desc": "Console Private Key"},  # Posiblemente para video y apps multimedia de la Xbox 360
    "KEY_0x34": {"offset": 0x0468, "size": 0x390, "desc": "XEIKA"},  # posiblemente para Xbox Live
    "KEY_0x35": {"offset": 0x07F8, "size": 0x1D0, "desc": "Cardea Private Key"},
    "KEY_0x36": {"offset": 0x09C8, "size": 0x1A8, "desc": "Console Certificate"},
    "KEY_0x37": {"offset": 0x0B72, "size": 0x140, "desc": "Cardea Certificate"},
    # Agrega aquí claves/certificados según vayan apareciendo
    # Hay 4 claves/certificados al offset 0x1EF8 pero estan en XML
    # De las 4 hay una con nivel 3000 que posiblemente sea importante
    # "KEY_0x38": {"offset": 0x1EF8, "size": 0x2108, "desc": "Cardea Certificate"},    
}
def read_keyvault(file_path):
    """Lee el archivo del KeyVault desencriptado."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"No se encontró el archivo {file_path}")
    with open(file_path, "rb") as f:
        return f.read()

def extract_rsa_key(data, key_name, desc, header_size=16, modulus_size=240):
    """Extrae la clave pública RSA de los datos de una clave/certificado."""
    try:
        # Extraer el módulo N (después del encabezado)
        header = data[:header_size]
        n_bytes = data[header_size:header_size + modulus_size]
        
        # Convertir a entero
        n_int = int.from_bytes(n_bytes, "big")
        
        # Validar que N sea impar
        if n_int % 2 == 0:
            print(f"Error: El módulo N en {key_name} es par, lo cual es incorrecto para una clave RSA.")
            return None
        
        # Construir la clave pública RSA
        public_key = RSA.construct((n_int, DEFAULT_E))
        
        # Exportar la clave pública
        pem_file = f"{key_name}_{desc}_PK.pem"
        with open(pem_file, "wb") as f:
            f.write(public_key.export_key())
        
        print(f"Clave pública extraída de {key_name} exitosamente.")
        
        # Mostrar información
        n_full = public_key.n.to_bytes(256, byteorder="big")
        print(f"{key_name} - Módulo N (hex): {n_full.hex()}")
        print(f"{key_name} - Exponente e: {public_key.e}")
        
        return public_key
    
    except Exception as e:
        print(f"Error al procesar {key_name}: {str(e)}")
        return None

def process_keyvault(keyvault_data):
    """Procesa todas las claves/certificados del KeyVault."""
    for key_name, info in KEY_VAULT_KEYS.items():
        offset = info["offset"]
        size = info["size"]
        desc = info["desc"]
        
        # Extraer los datos de la clave/certificado
        cert_data = keyvault_data[offset:offset + size]
        
        print(f"\nProcesando {key_name} ({desc})...")
        extract_rsa_key(cert_data, key_name, desc)

def main():
    # Ruta al archivo del KeyVault desencriptado
    keyvault_file = "keyvault_dec.bin"  # Ajusta según tu archivo
    
    # Leer el KeyVault
    keyvault_data = read_keyvault(keyvault_file)
    
    # Procesar todas las claves/certificados
    process_keyvault(keyvault_data)

if __name__ == "__main__":
    main()
