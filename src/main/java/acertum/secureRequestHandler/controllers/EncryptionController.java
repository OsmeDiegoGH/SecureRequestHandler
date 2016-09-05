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
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;

public class EncryptionController {
    
    private final EncryptionUtils encryptionUtils;
    private final ArrayUtils arrayUtils;
    private final KeyFactory RSAKeyFactory;
    
    private final String ENCRYPT_CHARSET_TYPE = "UTF-8";
    
    private final String RSA_ENCRYPT_KEY_ALGORITHM = "RSA";
    private final String RSA_ENCRYPT_ALGORITHM = "RSA/ECB/PKCS1Padding";    
    
    private final String AES_ENCRYPT_KEY_ALGORITHM = "AES"; 
    private final String AES_ENCRYPT_ALGORITHM = "AES/CBC/PKCS5Padding";  

    private final String SERVICE_PUBLIC_KEY_PATH = "/crypto/public_service.der";
    private final String CLIENT_PRIVATE_KEY_PATH = "/crypto/private_client.der";    
    
    private final SecretKey AES_SECRET_KEY;
    
    public EncryptionController() throws NoSuchAlgorithmException{
        encryptionUtils = EncryptionUtils.getInstance();
        arrayUtils = ArrayUtils.getInstance();
        RSAKeyFactory = KeyFactory.getInstance(this.RSA_ENCRYPT_KEY_ALGORITHM);
        
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ENCRYPT_KEY_ALGORITHM);
        keyGen.init(128);
        AES_SECRET_KEY = keyGen.generateKey();
    }
    
    public String GetAESKeyAsBase64(){
        return Base64.encode(AES_SECRET_KEY.getEncoded());
    }
    
    public String RSAencrypt(String content) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
        PublicKey publicKey = LoadRSAPublicServiceKey();
        byte[] encryptedBytes = encryptionUtils.encrypt(content.getBytes(ENCRYPT_CHARSET_TYPE), publicKey, RSA_ENCRYPT_ALGORITHM, false);
        return Base64.encode(encryptedBytes);
    }
    
    private PublicKey LoadRSAPublicServiceKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        InputStream inPublicKey = EncryptionController.class.getResourceAsStream( this.SERVICE_PUBLIC_KEY_PATH );
        byte[] keyBytes = arrayUtils.inputStreamToByteArray( inPublicKey );
        X509EncodedKeySpec spec = new X509EncodedKeySpec( keyBytes );
        return RSAKeyFactory.generatePublic( spec );         
    }
    
    public String RSAdecrypt(String base64content) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, Base64DecodingException{
        PrivateKey privateKey = LoadRSAPrivateClientKey();
        byte[] encryptedBytes = encryptionUtils.decrypt(Base64.decode(base64content), privateKey, RSA_ENCRYPT_ALGORITHM, false);
        return new String(encryptedBytes, ENCRYPT_CHARSET_TYPE);
    }
    
    private PrivateKey LoadRSAPrivateClientKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        InputStream inPrivateKey = EncryptionController.class.getResourceAsStream( this.CLIENT_PRIVATE_KEY_PATH );
        byte[] keyBytes = arrayUtils.inputStreamToByteArray( inPrivateKey );
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( keyBytes );
        return RSAKeyFactory.generatePrivate( spec );         
    }
    
    public String AESencrypt(String content) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, Base64DecodingException{
        byte[] encryptedBytes = encryptionUtils.encrypt(content.getBytes(ENCRYPT_CHARSET_TYPE), AES_SECRET_KEY, AES_ENCRYPT_ALGORITHM, true);
        return Base64.encode(encryptedBytes);
    }
    
    public String AESdecrypt(String base64Content) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, Base64DecodingException{
        byte[] encryptedBytes = encryptionUtils.decrypt(Base64.decode(base64Content), AES_SECRET_KEY, AES_ENCRYPT_ALGORITHM, true);
        return new String(encryptedBytes, ENCRYPT_CHARSET_TYPE);
    }
}