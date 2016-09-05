package acertum.secureRequestHandler.controllers;

import acertum.secureRequestHandler.utils.JSONUtils;
import acertum.secureRequestHandler.utils.RESTServiceUtils;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class SecureRequestController {
    
    private final JSONUtils jsonutils;
    public enum RESPONSE_CODE{
        SUCCESS,
        ERROR
    }
    
    public class Response{
        private RESPONSE_CODE code;
        private String response;
        
        public Response(RESPONSE_CODE code, String response){
            this.code = code;
            this.response = response;
        }

        public RESPONSE_CODE getCode() {
            return code;
        }

        public void setCode(RESPONSE_CODE code) {
            this.code = code;
        }

        public String getResponse() {
            return response;
        }

        public void setResponse(String response) {
            this.response = response;
        }
        
    }
    
    public SecureRequestController(){
        jsonutils = JSONUtils.getInstance(); 
    }
 
    public Response doPOST(String requestUrl, HashMap<String,String> parameters){
        return doRequest(requestUrl, "POST", parameters);
    }   

    public Response doGET(String requestUrl, HashMap<String,String> parameters){
        return doRequest(requestUrl, "GET", parameters);
    }     
    
    public Response doRequest(String requestUrl, String httpMethod, HashMap<String,String> parameters){
        try {
            EncryptionController encryptionController = new EncryptionController();
            
            HashMap<String,String> encryptedParameters = new HashMap<>();
            //AES encrypt parameters
            for (Map.Entry<String, String> mapEntry : parameters.entrySet()) {
                encryptedParameters.put(mapEntry.getKey(), encryptionController.AESencrypt(mapEntry.getValue()));
            }
            //Add RSA encrypt AESkey to request
            String base64AESKey = encryptionController.GetAESKeyAsBase64();
            encryptedParameters.put("transportKey", encryptionController.RSAencrypt(base64AESKey));
            
            //do POST request
            String encryptedBase64Response = RESTServiceUtils.RESTRequest(requestUrl, httpMethod, encryptedParameters);
            
            //AES decrypt response
            final String decryptedContent = encryptionController.AESdecrypt(encryptedBase64Response);

            return new Response(RESPONSE_CODE.SUCCESS, decryptedContent);            
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | Base64DecodingException ex) {
            return new Response(RESPONSE_CODE.ERROR, Arrays.toString(ex.getStackTrace()));
        }
    }
    
}
