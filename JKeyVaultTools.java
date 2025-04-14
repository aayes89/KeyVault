package jkeyvault;

/**
 *
 * @author Slam 
 * 
 * Código basado en los script de python del repositorio
 *
 */
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

public class DecryptKV {

    static final BigInteger DEFAULT_E = BigInteger.valueOf(65537); // 0x010001
    static final Map<String, KeyInfo> KEY_VAULT_KEYS = new HashMap<>();

    static {
        KEY_VAULT_KEYS.put("KEY_0x33", new KeyInfo(0x0298, 0x1D0, "Console Private Key"));
        KEY_VAULT_KEYS.put("KEY_0x34", new KeyInfo(0x0468, 0x390, "XEIKA"));
        KEY_VAULT_KEYS.put("KEY_0x35", new KeyInfo(0x07F8, 0x1D0, "Cardea Private Key"));
        KEY_VAULT_KEYS.put("KEY_0x36", new KeyInfo(0x09C8, 0x1A8, "Console Certificate"));
        KEY_VAULT_KEYS.put("KEY_0x37", new KeyInfo(0x0B72, 0x140, "Cardea Certificate"));
        KEY_VAULT_KEYS.put("KEY_0x38", new KeyInfo(0x1EF8, 0x2108, "Cardea Certificate"));
    }
    static final PublicKey[] PUBLIC_KEYS = new PublicKey[KEY_VAULT_KEYS.size()];

    // Obtiene un segmento del arreglo en bytes
    public static byte[] returnPortion(byte[] data, int start, int length) {
        return Arrays.copyOfRange(data, start, start + length);
    }

    // autenticar el mensaje con SHA1
    public static byte[] hmacSHA1(byte[] key, byte[] message) {
        try {
            SecretKeySpec signingKey = new SecretKeySpec(key, "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signingKey);
            return mac.doFinal(message);
        } catch (IllegalStateException | InvalidKeyException | NoSuchAlgorithmException e) {
            System.err.println("Exception: " + e.getMessage());
            return null;
        }
    }

    // aplicar RC4 para desencriptar los datos
    public static void rc4Decrypt(byte[] data, byte[] key) {
        try {
            SecretKeySpec rc4Key = new SecretKeySpec(key, "RC4");
            Cipher rc4 = Cipher.getInstance("RC4");
            rc4.init(Cipher.DECRYPT_MODE, rc4Key);
            byte[] decrypted = rc4.update(data);
            System.arraycopy(decrypted, 0, data, 0, data.length);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.err.println("Exception: " + e.getMessage());
        }
    }

    // desencriptar el KeyVault
    public static byte[] decryptKV(byte[] kv, byte[] key) {
        try {
            if (kv == null || key == null) {
                return null;
            }

            byte[] message = returnPortion(kv, 0, 0x10);
            byte[] RC4_key = hmacSHA1(key, message);
            if (RC4_key == null) {
                return null;
            }

            byte[] restOfKV = returnPortion(kv, 0x10, kv.length - 0x10);
            rc4Decrypt(restOfKV, returnPortion(RC4_key, 0, 0x10));

            byte[] finalImage = new byte[message.length + restOfKV.length];
            System.arraycopy(message, 0, finalImage, 0, message.length);
            System.arraycopy(restOfKV, 0, finalImage, message.length, restOfKV.length);

            return finalImage;

        } catch (Exception ex) {
            System.err.println(ex.getMessage());
        }
        return null;
    }

    // convierte cadena hexadecimal a arreglo de bytes (mejorable)
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // analisa el KV para extraer datos hardcodeados (facilitar el proceso de análisis posterior)
    public static void processKeyVault(byte[] kvData, String dir_path) {
        int count = 0;
        for (Map.Entry<String, KeyInfo> entry : KEY_VAULT_KEYS.entrySet()) {
            String keyName = entry.getKey();
            KeyInfo info = entry.getValue();
            System.out.println("\nProcesando " + keyName + " (" + info.desc + ")...");

            byte[] certData = Arrays.copyOfRange(kvData, info.offset, info.offset + info.size);
            // por optimizar
            PUBLIC_KEYS[count++] = extractRSAKey(certData, keyName, dir_path, info.desc, 16, 240);
        }
    }

    // escribe en formato PEM las claves públicas
    public static void writePEM(PublicKey publicKey, String path, String filename) throws IOException {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(publicKey.getEncoded());

        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + base64 + "\n"
                + "-----END PUBLIC KEY-----\n";

        //System.out.println("Direccion de las claves: " + path);
        Files.write(Paths.get(path + File.separator + filename), pem.getBytes());
    }

    // ajusta el tamaño del arreglo de entrada
    public static byte[] toFixedLength(byte[] input, int length) {
        if (input.length == length) {
            return input;
        }
        byte[] output = new byte[length];
        int start = length - input.length;
        System.arraycopy(input, 0, output, start, input.length);
        return output;
    }

    // convierte bytes a hexadecimal
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    // leer el fichero keyvault
    public static byte[] readKeyVault(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        if (!Files.exists(path)) {
            throw new FileNotFoundException("No se encontró el archivo " + filePath);
        }
        return Files.readAllBytes(path);
    }

    // extraer las llaves RSA del keyvault
    public static PublicKey extractRSAKey(byte[] data, String keyName, String dir_path, String desc, int headerSize, int modulusSize) {
        try {
            //byte[] header = Arrays.copyOfRange(data, 0, headerSize); // leer cabecera (determinar si es válida - no necesario ahora)
            byte[] nBytes = Arrays.copyOfRange(data, headerSize, headerSize + modulusSize); // extrae los bytes segun longitud
            BigInteger nInt = new BigInteger(1, nBytes);

            if (nInt.mod(BigInteger.valueOf(2L)).equals(BigInteger.ZERO)) {
                System.out.println("Error: El módulo N en " + keyName + " es par, lo cual es incorrecto para una clave RSA.");
                return null;
            }

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(nInt, DEFAULT_E);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            writePEM(publicKey, dir_path, keyName + "_" + desc.replace(" ", "_") + "_PK.pem");
            System.out.println("Clave pública extraída de " + keyName + " exitosamente.");

            byte[] nFull = toFixedLength(nInt.toByteArray(), 256);
            System.out.println(keyName + " - Módulo N (hex): " + bytesToHex(nFull));
            System.out.println(keyName + " - Exponente e: " + DEFAULT_E);

            return publicKey;

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Error al procesar " + keyName + ": " + e.getMessage());
            return null;
        }
    }

    // crear directorio para las claves extraidas
    public static File createDir(String dirPath) {
        File dirClaves = new File(dirPath, "claves");
        if (!dirClaves.exists()) {
            System.out.println(dirClaves.mkdir() ? ("Directorio \"" + dirClaves.getAbsolutePath() + "\" creado!") : ("No se pudo crear directorio: \"" + dirClaves.getAbsolutePath() + "\"!"));
        }
        return dirClaves;
    }

    public static void main(String[] args) throws Exception {
        // Ruta al directorio de la keyvault_enc.bin (cambiar o eliminar si es necesario)
        JFileChooser jfc = new JFileChooser("C:\\J-Runner-with-extras\\output");
        // Filtro para extensiones (agiliza la búsqueda del binario)
        jfc.setFileFilter(new FileNameExtensionFilter("Binario de KeyVault ", "bin"));
        // Muestra la ventana de explorador para elegir el binario
        jfc.showOpenDialog(null);
        // Carga el fichero seleccionado en kv_bin
        File kv_bin = jfc.getSelectedFile();
        if (kv_bin != null) {
            /* Fase 1 - Desencriptar Keyvault*/
            byte[] kv = readKeyVault(kv_bin.getAbsolutePath()); // Files.readAllBytes(kv_bin.toPath());
            byte[] cpuKey = hexStringToByteArray("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
            byte[] decryptedKV = decryptKV(kv, cpuKey);
            Files.write(Paths.get(kv_bin.getParent(), "keyvault_desencriptado.bin"), decryptedKV);
            System.out.println("KeyVault desencriptado!");
            System.out.println("Ruta: " + kv_bin.getParent());
            System.out.println("Fichero: keyvault_desencriptado.bin");

            /*Fase 2 - Extraer llaves públicas*/
            // crea un directorio claves donde se encuentra el keyvault
            System.out.println("Creando directorio para las claves...");            
            File clavesDir = createDir(kv_bin.getParent());    
            
            // escribe las claves públicas en formato PEM al directorio claves
            processKeyVault(decryptedKV, clavesDir.getAbsolutePath());

        } else {
            System.err.println("Error: Binario nulo o vacio!");
        }
    }

    static class KeyInfo {

        int offset, size;
        String desc;

        KeyInfo(int offset, int size, String desc) {
            this.offset = offset;
            this.size = size;
            this.desc = desc;
        }
    }
}
