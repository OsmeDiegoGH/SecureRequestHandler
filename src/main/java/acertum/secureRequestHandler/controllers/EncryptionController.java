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
    private final KeyFactory RSAKeyFactory;
    
    private final String ENCRYPT_CHARSET_TYPE = "UTF-8";
    
    private final String RSA_ENCRYPT_KEY_ALGORITHM = "RSA";
    private final String RSA_ENCRYPT_ALGORITHM = "RSA/ECB/PKCS1Padding";    
    
    private final String AES_ENCRYPT_KEY_ALGORITHM = "AES"; 
    private final String AES_ENCRYPT_ALGORITHM = "AES/CBC/PKCS5Padding";  
    
    private final String KEYS_PATH;
    
    private final String SERVICE_PUBLIC_KEY_NAME = "public_service.der";
    private PublicKey SERVICE_PUBLIC_KEY;
    private final String SERVICE_PRIVATE_KEY_NAME = "private_service.der";
    private PrivateKey SERVICE_PRIVATE_KEY;
    
    private final String CLIENT_PUBLIC_KEY_NAME = "public_client.der";
    private PublicKey CLIENT_PUBLIC_KEY;
    private final String CLIENT_PRIVATE_KEY_NAME = "private_client.der";
    private PrivateKey CLIENT_PRIVATE_KEY;
    
    private final Class CALLER_CLASS;
    
    public EncryptionController(String RSAKeysPath, Class<?> callerClass) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{
        encryptionUtils = EncryptionUtils.getInstance();
        arrayUtils = ArrayUtils.getInstance();
        RSAKeyFactory = KeyFactory.getInstance(this.RSA_ENCRYPT_KEY_ALGORITHM);
        CALLER_CLASS = callerClass;
        KEYS_PATH = RSAKeysPath;
    }
    
    public void LoadClientProfile() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException{
        LoadRSAPrivateClientKey();
        LoadRSAPublicServiceKey();
    }
    
    public void LoadServiceProfile() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        LoadRSAPrivateServiceKey();
        LoadRSAPublicClientKey();
    }
    
    private void LoadRSAPublicServiceKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        InputStream inPublicKey = CALLER_CLASS.getResourceAsStream( this.KEYS_PATH + this.SERVICE_PUBLIC_KEY_NAME );
        if(inPublicKey == null){
            throw new IOException("Can not load public service key");
        }
        byte[] keyBytes = arrayUtils.inputStreamToByteArray( inPublicKey );
        X509EncodedKeySpec spec = new X509EncodedKeySpec( keyBytes );
        SERVICE_PUBLIC_KEY = RSAKeyFactory.generatePublic( spec );         
    }
    
    private void LoadRSAPrivateServiceKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        InputStream inPrivateKey = CALLER_CLASS.getResourceAsStream( this.KEYS_PATH + this.SERVICE_PRIVATE_KEY_NAME );
        if(inPrivateKey == null){
            throw new IOException("Can not load private service key");
        }
        byte[] keyBytes = arrayUtils.inputStreamToByteArray( inPrivateKey );
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( keyBytes );
        SERVICE_PRIVATE_KEY = RSAKeyFactory.generatePrivate( spec );         
    }
    
    private void LoadRSAPublicClientKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        InputStream inPublicKey = CALLER_CLASS.getResourceAsStream( this.KEYS_PATH + this.CLIENT_PUBLIC_KEY_NAME );
        if(inPublicKey == null){
            throw new IOException("Can not load public service key");
        }
        byte[] keyBytes = arrayUtils.inputStreamToByteArray( inPublicKey );
        X509EncodedKeySpec spec = new X509EncodedKeySpec( keyBytes );
        CLIENT_PUBLIC_KEY = RSAKeyFactory.generatePublic( spec );         
    }
    
    private void LoadRSAPrivateClientKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        InputStream inPrivateKey = CALLER_CLASS.getResourceAsStream( this.KEYS_PATH + this.CLIENT_PRIVATE_KEY_NAME );
        if(inPrivateKey == null){
            throw new IOException("Can not load private service key");
        }
        byte[] keyBytes = arrayUtils.inputStreamToByteArray( inPrivateKey );
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( keyBytes );
        CLIENT_PRIVATE_KEY = RSAKeyFactory.generatePrivate( spec );         
    }
    
    public String GenerateAESKey() throws NoSuchAlgorithmException{
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ENCRYPT_KEY_ALGORITHM);
        keyGen.init(128);
        return Base64.encode(keyGen.generateKey().getEncoded());
    }
    
    public String RSAClientEncrypt(String content) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
        byte[] encryptedBytes = encryptionUtils.encrypt(content.getBytes(ENCRYPT_CHARSET_TYPE), SERVICE_PUBLIC_KEY, RSA_ENCRYPT_ALGORITHM, false);
        return Base64.encode(encryptedBytes);
    }
    
    public String RSAServiceEncrypt(String content) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
        byte[] encryptedBytes = encryptionUtils.encrypt(content.getBytes(ENCRYPT_CHARSET_TYPE), CLIENT_PUBLIC_KEY, RSA_ENCRYPT_ALGORITHM, false);
        return Base64.encode(encryptedBytes);
    }
    
    public String RSAClientDecrypt(String base64content) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, Base64DecodingException{
        byte[] encryptedBytes = encryptionUtils.decrypt(Base64.decode(base64content), CLIENT_PRIVATE_KEY, RSA_ENCRYPT_ALGORITHM, false);
        return new String(encryptedBytes, ENCRYPT_CHARSET_TYPE);
    }
    
    public String RSAServiceDecrypt(String base64content) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, Base64DecodingException{
        byte[] encryptedBytes = encryptionUtils.decrypt(Base64.decode(base64content), SERVICE_PRIVATE_KEY, RSA_ENCRYPT_ALGORITHM, false);
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