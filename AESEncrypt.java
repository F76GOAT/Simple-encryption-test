package f76goat.encryption.AES;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AESEncrypt {
    
    public String encryptAES(String data, SecretKey key, IvParameterSpec iv) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        byte[] ivAndCipherText = new byte[iv.getIV().length + encrypted.length];
        System.arraycopy(iv.getIV(), 0, ivAndCipherText, 0, iv.getIV().length);
        System.arraycopy(encrypted, 0, ivAndCipherText, iv.getIV().length, encrypted.length);
        return Base64.getEncoder().encodeToString(ivAndCipherText);
    }
    
}
