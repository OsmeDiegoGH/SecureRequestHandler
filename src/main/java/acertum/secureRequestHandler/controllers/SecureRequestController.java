package acertum.secureRequestHandler.controllers;

import acertum.secureRequestHandler.entities.RequestResponse;
import acertum.secureRequestHandler.utils.RESTServiceUtils;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

public class SecureRequestController {
   
    private final EncryptionController encryptionController;
    public enum REQUEST_MODE {
        CLIENT,
        SERVICE
    }
    
    public SecureRequestController(String RSAKeysPath, Class<?> callerClass, REQUEST_MODE mode) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{
        com.sun.org.apache.xml.internal.security.Init.init();
        encryptionController = new EncryptionController(RSAKeysPath, callerClass);
        if(mode == REQUEST_MODE.CLIENT){
            encryptionController.LoadClientProfile();
        }else{
            encryptionController.LoadServiceProfile();
        }
    }
 
    public RequestResponse doSecurePOST(String requestUrl, HashMap<String,String> parameters){
        return doSecureRequest(requestUrl, "POST", parameters);
    }   

    public RequestResponse doSecureGET(String requestUrl, HashMap<String,String> parameters){
        return doSecureRequest(requestUrl, "GET", parameters);
    }     
    
    public RequestResponse doSecureRequest(String requestUrl, String httpMethod, HashMap<String,String> parameters){
        try {
            String base64AESKey = encryptionController.GenerateAESKey();
            HashMap<String,String> encryptedParameters = new HashMap<>();
            //AES encrypt parameters
            for (Map.Entry<String, String> mapEntry : parameters.entrySet()) {
                encryptedParameters.put(mapEntry.getKey(), encryptionController.AESencrypt(mapEntry.getValue(), base64AESKey));
            }
            //Add RSA encrypt AESkey to request
            encryptedParameters.put("transportKey", encryptionController.RSAClientEncrypt(base64AESKey));
            
            //do request
            String encryptedBase64Response = RESTServiceUtils.RESTRequest(requestUrl, httpMethod, encryptedParameters);
            
            //AES decrypt response
            final String decryptedContent = encryptionController.AESdecrypt(encryptedBase64Response, base64AESKey);

            return new RequestResponse(RequestResponse.RESPONSE_CODE.SUCCESS, decryptedContent);            
        } catch (Exception ex) {
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, ex.getMessage());
        }
    }
    
    public RequestResponse doPOST(String requestUrl, HashMap<String,String> parameters){
        return doRequest(requestUrl, "POST", parameters);
    }   

    public RequestResponse doGET(String requestUrl, HashMap<String,String> parameters){
        return doRequest(requestUrl, "POST", parameters);
    }    
    
    public RequestResponse doRequest(String requestUrl, String httpMethod, HashMap<String,String> parameters){
        try {
            String response = RESTServiceUtils.RESTRequest(requestUrl, httpMethod, parameters);
            return new RequestResponse(RequestResponse.RESPONSE_CODE.SUCCESS, response);            
        } catch (Exception ex) {
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, ex.toString());
        }
    }    
}
