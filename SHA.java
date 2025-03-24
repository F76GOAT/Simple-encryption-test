package f76goat.encryption.SHA;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SHA {
    
    public static String encryptSHA(String data) throws NoSuchAlgorithmException {
        String saltedData = data + saltGenerator();
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] hash = digest.digest(saltedData.getBytes());
        
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        
        return hexString.toString();
        
    }
    
    public static String saltGenerator() {
        byte[] salt = new byte[256];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }
    
}
