package acertum.secureRequestHandler.controllers;

import acertum.secureRequestHandler.entities.RequestResponse;
import acertum.secureRequestHandler.utils.RESTServiceUtils;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class SecureRequestController {
   
    private final EncryptionController encryptionController;
    public enum REQUEST_MODE {
        CLIENT,
        SERVICE
    }
    
    public SecureRequestController(String RSAKeysPath, Class<?> callerClass, REQUEST_MODE mode) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{
        encryptionController = new EncryptionController(RSAKeysPath, callerClass);
        if(mode == REQUEST_MODE.CLIENT){
            encryptionController.LoadClientProfile();
        }else{
            encryptionController.LoadServiceProfile();
        }
    }
 
    public RequestResponse doPOST(String requestUrl, HashMap<String,String> parameters){
        return doRequest(requestUrl, "POST", parameters);
    }   

    public RequestResponse doGET(String requestUrl, HashMap<String,String> parameters){
        return doRequest(requestUrl, "GET", parameters);
    }     
    
    public RequestResponse doRequest(String requestUrl, String httpMethod, HashMap<String,String> parameters){
        try {
            String base64AESKey = encryptionController.GenerateAESKey();
            HashMap<String,String> encryptedParameters = new HashMap<>();
            //AES encrypt parameters
            for (Map.Entry<String, String> mapEntry : parameters.entrySet()) {
                encryptedParameters.put(mapEntry.getKey(), encryptionController.AESencrypt(mapEntry.getValue(), base64AESKey));
            }
            //Add RSA encrypt AESkey to request
            encryptedParameters.put("transportKey", encryptionController.RSAClientEncrypt(base64AESKey));
            
            //do POST request
            String encryptedBase64Response = RESTServiceUtils.RESTRequest(requestUrl, httpMethod, encryptedParameters);
            
            //AES decrypt response
            final String decryptedContent = encryptionController.AESdecrypt(encryptedBase64Response, base64AESKey);

            return new RequestResponse(RequestResponse.RESPONSE_CODE.SUCCESS, decryptedContent);            
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | Base64DecodingException ex) {
            ex.printStackTrace();
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, ex.getMessage());
        }
    }
    
}
