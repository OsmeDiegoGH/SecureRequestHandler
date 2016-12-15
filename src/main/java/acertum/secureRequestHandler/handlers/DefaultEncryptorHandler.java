package acertum.secureRequestHandler.handlers;

import acertum.secureRequestHandler.helpers.AESEncryptorHelper;
import acertum.secureRequestHandler.helpers.RSAEncryptorHelper;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class DefaultEncryptorHandler implements IRequestHandler{
    
    private final int AES_KEY_LENGTH = 128; 
    private String DYNAMIC_AES_KEY;
    private final RSAEncryptorHelper rsaEncryptorHaelper;   
    private final AESEncryptorHelper aesEncryptorHandler; 
    
    private String resourcesPathRSAPublicKey = "/crypto/public.der";
    private String resourcesPathRSAPrivateKey = "/crypto/private.der";
    
    public DefaultEncryptorHandler(Class<?> callerClass){
        this.rsaEncryptorHaelper = new RSAEncryptorHelper(callerClass);
        this.aesEncryptorHandler = new AESEncryptorHelper();
    }
    
    public void setPublicRSAKeyPath(String keyPath){
        this.resourcesPathRSAPublicKey = keyPath;
    }
    
    public void setPrivateRSAKeyPath(String keyPath){
        this.resourcesPathRSAPrivateKey = keyPath;
    }
        
    @Override
    public void prepare(String requestUrl, String httpMethod, String contentType, HashMap<String,String> secureParameters, HashMap<String,String> rawParameters) throws Exception{
        PublicKey rsaPublicKey;
        try {
            rsaPublicKey = this.rsaEncryptorHaelper.loadPublicKeyFromResources(this.resourcesPathRSAPublicKey);
        } catch (Exception ex) {
            throw new Exception("Error al generar cargar llave RSA - " + ex.getMessage());
        }  
        
        try {
            this.DYNAMIC_AES_KEY = aesEncryptorHandler.GenerateKey(this.AES_KEY_LENGTH);
        } catch (Exception ex) {
            throw new Exception("Error al generar la llave dinámica - " + ex.getMessage());
        }  
        rawParameters.put("transportKey", this.rsaEncryptorHaelper.encrypt(this.DYNAMIC_AES_KEY, rsaPublicKey));
    }
    
    @Override
    public String encrypt(String rawParameter) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, Base64DecodingException {
        return this.aesEncryptorHandler.encrypt(rawParameter, this.DYNAMIC_AES_KEY);
    }
    
    public String encrypt(String rawParameter, String aesKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, Base64DecodingException {
        return this.aesEncryptorHandler.encrypt(rawParameter, aesKey);
    }
    
    @Override
    public String decrypt(String encryptedText) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, Base64DecodingException{
        return this.aesEncryptorHandler.decrypt(encryptedText, this.DYNAMIC_AES_KEY);
    }
    
    public String decrypt(String encryptedText, String aesKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, Base64DecodingException{
        return this.aesEncryptorHandler.decrypt(encryptedText, aesKey);
    }
        
    public String RSAdecrypt(String encryptedText) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, Base64DecodingException, IllegalBlockSizeException, UnsupportedEncodingException, BadPaddingException, InvalidAlgorithmParameterException{
        PrivateKey rsaPrivateKey = this.rsaEncryptorHaelper.loadPrivateKeyFromResources(this.resourcesPathRSAPrivateKey);
        return this.rsaEncryptorHaelper.decrypt(encryptedText, rsaPrivateKey);
    }
}
