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

public class AESDecrypt {
    
    public static String decrypAES(String encryptedData, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] ivBytes = new byte[16];
        byte[] cipherText = new byte[decoded.length - 16];
        
        System.arraycopy(decoded, 0, ivBytes, 0, 16);
        System.arraycopy(decoded, 16, cipherText, 0, cipherText.length);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
        byte[] decrypted = cipher.doFinal(cipherText);
        
        return new String(decrypted);
    }
    
}
