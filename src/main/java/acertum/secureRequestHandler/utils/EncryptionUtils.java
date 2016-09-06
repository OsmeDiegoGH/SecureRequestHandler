package acertum.secureRequestHandler.utils;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class EncryptionUtils {
    
    private static final EncryptionUtils INSTANCE = new EncryptionUtils();
    
    private EncryptionUtils(){}
    
    public static EncryptionUtils getInstance(){
        return INSTANCE;
    }
    
    public byte[] encrypt(byte[] content, Key key,  String encryptType, boolean useVector) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, BadPaddingException {
        final Cipher cipher = Cipher.getInstance(encryptType);
        if(useVector){
            IvParameterSpec ivParameterSpec = new IvParameterSpec(key.getEncoded());
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        }else{
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        return cipher.doFinal(content);
    }
    
    public byte[] decrypt(byte[] content, Key key, String encryptType, boolean useVector) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, BadPaddingException {
        final Cipher decipher = Cipher.getInstance(encryptType);
        if(useVector){
            IvParameterSpec ivParameterSpec = new IvParameterSpec(key.getEncoded());
            decipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        }else{
            decipher.init(Cipher.DECRYPT_MODE, key);
        }
        return decipher.doFinal(content);
    }   
    
    public String FixBadRequestTransportChar(String base64Content){
        return base64Content.replace(' ', '+');
    }
       
    /*public KeyPair generateKeyPair(String keyAlgorithm, int keySize) throws NoSuchAlgorithmException{
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }
    
    public PublicKey bytesToPublicKey(byte[] keyBytes, String keyAlgorithm) throws NoSuchAlgorithmException, InvalidKeySpecException{
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance(keyAlgorithm).generatePublic( keySpec );
    }
    
    public PrivateKey bytesToPrivateKey(byte[] keyBytes, String keyAlgorithm) throws NoSuchAlgorithmException, InvalidKeySpecException{
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance(keyAlgorithm).generatePrivate( keySpec );
    }*/
}

