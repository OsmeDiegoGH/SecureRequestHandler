package acertum.secureRequestHandler.controllers;

import acertum.secureRequestHandler.utils.ArrayUtils;
import acertum.secureRequestHandler.utils.EncryptionUtils;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionController {
    
    private final EncryptionUtils encryptionUtils;
    private final ArrayUtils arrayUtils;
    
    private final String ENCRYPT_CHARSET_TYPE = "UTF-8";
    
    private final String RSA_ENCRYPT_KEY_ALGORITHM = "RSA";
    private final String RSA_ENCRYPT_ALGORITHM = "RSA/ECB/PKCS1Padding";    
    
    private final String AES_ENCRYPT_KEY_ALGORITHM = "AES"; 
    private final String AES_ENCRYPT_ALGORITHM = "AES/CBC/PKCS5Padding";  
    private final Class CALLER_CLASS;
    
    public EncryptionController(Class<?> callerClass){
        encryptionUtils = EncryptionUtils.getInstance();
        arrayUtils = ArrayUtils.getInstance();
        CALLER_CLASS = callerClass;
    }
    
    public PublicKey loadRSAPublicKeyFromResources(String keyPath) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException{
        InputStream inPublicKey = CALLER_CLASS.getResourceAsStream( keyPath );
        if(inPublicKey == null){
            throw new IOException("Can not load public key from path: " + keyPath);
        }
        byte[] keyBytes = arrayUtils.inputStreamToByteArray( inPublicKey );
        X509EncodedKeySpec spec = new X509EncodedKeySpec( keyBytes );
        return KeyFactory.getInstance(this.RSA_ENCRYPT_KEY_ALGORITHM).generatePublic( spec );   
    }
    
    public PrivateKey loadRSAPrivateKeyFromResources(String keyPath) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException{
        InputStream inPrivateKey = CALLER_CLASS.getResourceAsStream( keyPath );
        if(inPrivateKey == null){
            throw new IOException("Can not load private key from path: " + keyPath);
        }
        byte[] keyBytes = arrayUtils.inputStreamToByteArray( inPrivateKey );
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( keyBytes );
        return KeyFactory.getInstance(this.RSA_ENCRYPT_KEY_ALGORITHM).generatePrivate( spec ); 
    }

    public String GenerateAESKey() throws NoSuchAlgorithmException{
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ENCRYPT_KEY_ALGORITHM);
        keyGen.init(128);
        return Base64.encode(keyGen.generateKey().getEncoded());
    }
    
    public String RSAEncrypt(String content, PublicKey publicKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
        byte[] encryptedBytes = encryptionUtils.encrypt(content.getBytes(ENCRYPT_CHARSET_TYPE), publicKey, RSA_ENCRYPT_ALGORITHM, false);
        return Base64.encode(encryptedBytes);
    }
    
    public String RSADecrypt(String base64content, PrivateKey privateKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, Base64DecodingException{
        byte[] encryptedBytes = encryptionUtils.decrypt(Base64.decode(base64content), privateKey, RSA_ENCRYPT_ALGORITHM, false);
        return new String(encryptedBytes, ENCRYPT_CHARSET_TYPE);
    }
    
    public String AESencrypt(String content, String base64SecretKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, Base64DecodingException{
        SecretKey secretKey = new SecretKeySpec(Base64.decode(base64SecretKey), AES_ENCRYPT_KEY_ALGORITHM);
        byte[] encryptedBytes = encryptionUtils.encrypt(content.getBytes(ENCRYPT_CHARSET_TYPE), secretKey, AES_ENCRYPT_ALGORITHM, true);
        return Base64.encode(encryptedBytes);
    }
    
    public String AESdecrypt(String base64Content, String base64SecretKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, Base64DecodingException{
        SecretKey secretKey = new SecretKeySpec(Base64.decode(base64SecretKey), AES_ENCRYPT_KEY_ALGORITHM);
        byte[] encryptedBytes = encryptionUtils.decrypt(Base64.decode(base64Content), secretKey, AES_ENCRYPT_ALGORITHM, true);
        return new String(encryptedBytes, ENCRYPT_CHARSET_TYPE);
    }
}