package acertum.secureRequestHandler.helpers;

import acertum.secureRequestHandler.utils.EncryptionUtils;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class AESEncryptorHelper {
 
    private final EncryptionUtils encryptionUtils = EncryptionUtils.getInstance();
    private final String ENCRYPT_KEY_ALGORITHM = "AES";  
    private final String ENCRYPT_ALGORITHM = "AES/CBC/PKCS5Padding";  
    private final String ENCRYPT_CHARSET_TYPE = "UTF-8";
    
    public String GenerateKey(int keyLength) throws NoSuchAlgorithmException{
        KeyGenerator keyGen = KeyGenerator.getInstance(this.ENCRYPT_KEY_ALGORITHM);
        keyGen.init(keyLength);
        return Base64.encode(keyGen.generateKey().getEncoded());
    }   
    
    public String encrypt(String content, String base64SecretKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, Base64DecodingException{
        SecretKey secretKey = new SecretKeySpec(Base64.decode(base64SecretKey), this.ENCRYPT_KEY_ALGORITHM);
        byte[] encryptedBytes = encryptionUtils.encrypt(content.getBytes(this.ENCRYPT_CHARSET_TYPE), secretKey, this.ENCRYPT_ALGORITHM, true);
        return Base64.encode(encryptedBytes);
    }
    
    public String decrypt(String base64Content, String base64SecretKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, Base64DecodingException{
        SecretKey secretKey = new SecretKeySpec(Base64.decode(base64SecretKey), this.ENCRYPT_KEY_ALGORITHM);
        byte[] encryptedBytes = encryptionUtils.decrypt(Base64.decode(base64Content), secretKey, this.ENCRYPT_ALGORITHM, true);
        return new String(encryptedBytes, ENCRYPT_CHARSET_TYPE);
    }
}
