package acertum.secureRequestHandler.controllers;

import acertum.secureRequestHandler.entities.RequestResponse;
import acertum.secureRequestHandler.utils.EncryptionUtils;
import acertum.secureRequestHandler.utils.RESTServiceUtils;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

public class SecureRequestController {
   
    private final EncryptionController encryptionController;
    private PublicKey RSA_PUBLIC_KEY;
    private PrivateKey RSA_PRIVATE_KEY;
    
    public SecureRequestController(Class<?> callerClass){
        encryptionController = new EncryptionController(callerClass);
    }
    
    public void loadKeysFromResources(String RSA_publicKeyPath, String RSA_privateKeyPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{
        com.sun.org.apache.xml.internal.security.Init.init();
        RSA_PUBLIC_KEY = encryptionController.loadRSAPublicKeyFromResources(RSA_publicKeyPath);
        RSA_PRIVATE_KEY = encryptionController.loadRSAPrivateKeyFromResources(RSA_privateKeyPath);
    }
     
    public RequestResponse doSecurePOST(String requestUrl, HashMap<String,String> secureParameters){
        return doSecureRequest(requestUrl, "POST", secureParameters, null, false);
    } 
    
    public RequestResponse doSecurePOST(String requestUrl, HashMap<String,String> secureParameters, HashMap<String,String> rawParameters){
        return doSecureRequest(requestUrl, "POST", secureParameters, rawParameters, false);
    } 
    
    public RequestResponse doSecurePOST(String requestUrl, HashMap<String,String> secureParameters, HashMap<String,String> rawParameters, boolean ignoreSSL){
        return doSecureRequest(requestUrl, "POST", secureParameters, rawParameters, ignoreSSL);
    } 

    public RequestResponse doSecureGET(String requestUrl, HashMap<String,String> secureParameters){
        return doSecureRequest(requestUrl, "GET", secureParameters, null, false);
    }  
    
    public RequestResponse doSecureGET(String requestUrl, HashMap<String,String> secureParameters, HashMap<String,String> rawParameters){
        return doSecureRequest(requestUrl, "GET", secureParameters, rawParameters, false);
    }  
    
    public RequestResponse doSecureGET(String requestUrl, HashMap<String,String> secureParameters, HashMap<String,String> rawParameters, boolean ignoreSSL){
        return doSecureRequest(requestUrl, "GET", secureParameters, rawParameters, ignoreSSL);
    }  

    
    public RequestResponse doSecureRequest(String requestUrl, String httpMethod, HashMap<String,String> secureParameters, HashMap<String,String> rawParameters, boolean ignoreSSL){
        String base64AESKey;
        try {
            base64AESKey = encryptionController.GenerateAESKey();
        } catch (Exception ex) {
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error al generar la llave dinámica - " + ex.getMessage());
        }
        
        HashMap<String,String> requestParameters = new HashMap();
        try {
            //AES encrypt parameters
            for (Map.Entry<String, String> mapEntry : secureParameters.entrySet()) {
                requestParameters.put(mapEntry.getKey(), encryptionController.AESencrypt(mapEntry.getValue(), base64AESKey));
            }
        } catch (Exception ex) {
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error al encriptar los parámetros de la petición - " + ex.getMessage());
        }
        
        try {
            //Add RSA encrypt AESkey to request
            requestParameters.put("transportKey", encryptionController.RSAEncrypt(base64AESKey, RSA_PUBLIC_KEY));
        } catch (Exception ex) {
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error al encriptar llave dinámica - " + ex.getMessage());
        }
        if(rawParameters != null){
            requestParameters.putAll(rawParameters);
        }
        
        //do request
        boolean isHTTPSRequest = requestUrl.startsWith("https://");
        String encryptedBase64Response;
        String httpsProtocols = System.getProperty("https.protocols") != null ? System.getProperty("https.protocols") : "";
        
        try {
            if (isHTTPSRequest) {
                if(ignoreSSL){
                    RESTServiceUtils.ignoreSSL();
                }else{
                    //force http request to use TLSv1 protocol
                    System.setProperty("https.protocols", "TLSv1");
                }
            }
            encryptedBase64Response = RESTServiceUtils.RESTRequest(requestUrl, httpMethod, "application/x-www-form-urlencoded;charset=UTF-8", requestParameters);
            System.setProperty("https.protocols", httpsProtocols);
        } catch (Exception ex) {
            System.setProperty("https.protocols", httpsProtocols);
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error en el consumo de la petición - " + ex.toString());
        }

        //AES decrypt response
        final String decryptedContent;
        try {
            decryptedContent = encryptionController.AESdecrypt(EncryptionUtils.getInstance().FixBadRequestTransportChar(encryptedBase64Response), base64AESKey);
        } catch (Exception ex) {
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error: " + ex.toString()+ ", al desencriptar la respuesta del servicio --- respuesta: " + encryptedBase64Response);
        }

        return new RequestResponse(RequestResponse.RESPONSE_CODE.SUCCESS, decryptedContent); 
    }
    
    public RequestResponse doPOST(String requestUrl, HashMap<String,String> parameters){
        return doRequest(requestUrl, "POST", "application/x-www-form-urlencoded;charset=UTF-8", parameters);
    } 

    public RequestResponse doGET(String requestUrl, HashMap<String,String> parameters){
        return doRequest(requestUrl, "POST", "application/x-www-form-urlencoded;charset=UTF-8", parameters);
    } 
    
    public RequestResponse doRequest(String requestUrl, String httpMethod, String contentType, HashMap<String,String> parameters){
        try {
            String response = RESTServiceUtils.RESTRequest(requestUrl, httpMethod, contentType, parameters);
            return new RequestResponse(RequestResponse.RESPONSE_CODE.SUCCESS, response);            
        } catch (Exception ex) {
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, ex.toString());
        }
    }    
}
