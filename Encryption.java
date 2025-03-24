package f76goat.encryption;

import f76goat.encryption.AES.AESDecrypt;
import f76goat.encryption.AES.AESEncrypt;
import static f76goat.encryption.AES.AESKeyGen.generateAESKey;
import static f76goat.encryption.AES.AESKeyGen.generateIV;
import f76goat.encryption.RSA.RSADecrypt;
import f76goat.encryption.RSA.RSAEncrypt;
import f76goat.encryption.RSA.RSAKeyGen;
import f76goat.encryption.SHA.SHA;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Encryption {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, BadPaddingException, InvalidAlgorithmParameterException {
        AESEncrypt aesEncryptor = new AESEncrypt();
        SecretKey key = generateAESKey();
        IvParameterSpec iv = generateIV();
        KeyPair keyPairRSA = RSAKeyGen.keyPairGen();

        String plainText = "Secret message hehe";
        String encryptedTextAES = aesEncryptor.encryptAES(plainText, key, iv);
        String decryptedTextAES = AESDecrypt.decrypAES(encryptedTextAES, key);
        String shaHash = SHA.encryptSHA(plainText);
        String encryptedTextRSA = RSAEncrypt.encryptRSA(plainText, keyPairRSA.getPublic());
        String decryptedTextRSA = RSADecrypt.decrptyRSA(encryptedTextRSA, keyPairRSA.getPrivate());

        System.out.println("Raw data: " + plainText);
        System.out.println("AES Encrypted data: " + encryptedTextAES);
        System.out.println("AES Decryoted data: " + decryptedTextAES);
        System.out.println("SSH-512 hash: " + shaHash);
        System.out.println("RSA Encrypted data: " + encryptedTextRSA);
        System.out.println("RSA Decrypted data: " + decryptedTextRSA);
    }
}
