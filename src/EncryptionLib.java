import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Formatter;

import static java.nio.charset.StandardCharsets.UTF_8;

public class EncryptionLib {
    private PublicKey publicKey;
    private PrivateKey privateKey;

    private static final String HMAC_SHA512 = "HmacSHA512";

    public EncryptionLib(PublicKey pubkey, PrivateKey privkey) {
        this.publicKey = pubkey;
        this.privateKey = privkey;
    }

    /**
     * plainText wird mit dem RSA-Key der Klasse verschlüsselt und als Base64 zurückgegeben.
     */
    public String RSAencryptMessage(String plainText) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     * cipherText (im Base64-Format) wird mit dem RSA-Key der Klasse entchlüsselt und als Text zurückgegeben.
     */
    public String RSAdecryptMessage(String cipherText) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public String rawRSAEncrypt(String cleartext, PublicKey pub) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, pub);

        byte[] cipherText = encryptCipher.doFinal(cleartext.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String stripString(String orig) {
        // Sowohl \n als auch \r Sequenzen werden aus Strings entfernt, um sie zu gültigen Keys zu machen (verhindert EOF Probleme).
        return orig.replace("\n", "").replace("\r", "").replace(" ", "");
    }

    public String AESdecrypt(String ciphertext, Key aesKey) throws Exception {
        byte[] keyBytes = aesKey.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        byte[] cipherBytes = Base64.getDecoder().decode(ciphertext);

        // Entschluesseln
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] clearBytes = cipher.doFinal(cipherBytes);

        return new String(clearBytes);
    }

    public String AESencrypt(String cleartext, Key aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] keyBytes = aesKey.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encrypted = cipher.doFinal(cleartext.getBytes());

        return new String(Base64.getEncoder().encode(encrypted));
    }

    public static PublicKey PublicKeyFromString(String key) throws Exception {
        // Der String wird in einen byte[] Array knovertiert und dekodiert.
        byte[] keyBytes = Base64.getDecoder().decode(key);

        // Der byte[] Array wird genutzt um einen Key zu konstruieren
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public Key AESKeyFromString(String key) throws Exception {
        // Stunden an dieser Methode verschwendet: 3
        byte[] decodedKey = Base64.getDecoder().decode(key);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    // Erstellen eines SHA512 Hashes
    public static String get_SHA_512(String passwordToHash, String salt){
        String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] bytes = md.digest(passwordToHash.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for(int i=0; i< bytes.length ;i++){
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
    }

    public static KeyPair generateRSAKeypair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        return keyPairGen.generateKeyPair();
    }

    private static String toHexString(byte[] bytes) {
        Formatter formatter = new Formatter();
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    public static String calculateHMAC(String data, String key) throws Exception
    {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), HMAC_SHA512);
        Mac mac = Mac.getInstance(HMAC_SHA512);
        mac.init(secretKeySpec);
        return toHexString(mac.doFinal(data.getBytes()));
    }
}
