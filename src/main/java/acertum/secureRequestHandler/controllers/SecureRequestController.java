package acertum.secureRequestHandler.controllers;

import acertum.secureRequestHandler.entities.RequestResponse;
import acertum.secureRequestHandler.utils.RESTServiceUtils;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
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
        String base64AESKey;
        try {
            base64AESKey = encryptionController.GenerateAESKey();
        } catch (NoSuchAlgorithmException ex) {
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error al generar la llave dinámica - " + ex.getMessage());
        }
        
        HashMap<String,String> encryptedParameters = new HashMap<>();
        try {
            //AES encrypt parameters
            for (Map.Entry<String, String> mapEntry : parameters.entrySet()) {
                encryptedParameters.put(mapEntry.getKey(), encryptionController.AESencrypt(mapEntry.getValue(), base64AESKey));
            }
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | Base64DecodingException ex) {
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error al encriptar los parámetros de la petición - " + ex.getMessage());
        }
        
        try {
            //Add RSA encrypt AESkey to request
            encryptedParameters.put("transportKey", encryptionController.RSAClientEncrypt(base64AESKey));
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException ex) {
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error al encriptar llave dinámica - " + ex.getMessage());
        }

        //do request
        String encryptedBase64Response;
        try {
            encryptedBase64Response = RESTServiceUtils.RESTRequest(requestUrl, httpMethod, encryptedParameters);
        } catch (Exception ex) {
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error en el consumo de la petición - " + ex.getMessage());
        }

        //AES decrypt response
        final String decryptedContent;
        try {
            decryptedContent = encryptionController.AESdecrypt(encryptedBase64Response, base64AESKey);
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | Base64DecodingException ex) {
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error al desencriptar la respuesta de la petición - " + ex.getMessage());
        }

        return new RequestResponse(RequestResponse.RESPONSE_CODE.SUCCESS, decryptedContent); 
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
