package acertum.secureRequestHandler.controllers;

import acertum.secureRequestHandler.entities.RequestResponse;
import acertum.secureRequestHandler.utils.EncryptionUtils;
import acertum.secureRequestHandler.utils.RESTServiceUtils;
import acertum.secureRequestHandler.utils.RSACustom;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

public class SecureRequestController {
   
    private final EncryptionController encryptionController;
    private final RSACustom rsaCustom;
    private PublicKey RSA_PUBLIC_SERVICE_KEY;
    private PrivateKey RSA_PRIVATE_CLIENT_KEY;
    private PublicKey CUSTOM_RSA_PUBLIC_SERVICE_KEY;
    private PrivateKey CUSTOM_RSA_PRIVATE_CLIENT_KEY;
    
    public SecureRequestController(Class<?> callerClass){
        com.sun.org.apache.xml.internal.security.Init.init();
        encryptionController = new EncryptionController(callerClass);
        rsaCustom = new RSACustom(callerClass);
    }
    
    public void loadRSAKeysFromResources(String RSA_publicServiceKeyPath, String RSA_privateClientKeyPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{
        this.RSA_PUBLIC_SERVICE_KEY = this.encryptionController.loadRSAPublicKeyFromResources(RSA_publicServiceKeyPath);
        this.RSA_PRIVATE_CLIENT_KEY = this.encryptionController.loadRSAPrivateKeyFromResources(RSA_privateClientKeyPath);
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
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error al encriptar los parametros de la peticion - " + ex.getMessage());
        }
        
        try {
            //Add RSA encrypt AESkey to request
            requestParameters.put("transportKey", encryptionController.RSAEncrypt(base64AESKey, RSA_PUBLIC_SERVICE_KEY));
        } catch (Exception ex) {
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error al encriptar llave dinámica - " + ex.getMessage());
        }
        if(rawParameters != null){
            requestParameters.putAll(rawParameters);
        }
        
        RequestResponse response = doRequest(requestUrl, httpMethod, "application/x-www-form-urlencoded;charset=UTF-8", requestParameters);
        if(response.getCode() == RequestResponse.RESPONSE_CODE.ERROR){
            return response;
        }

        //AES decrypt response
        final String decryptedContent;
        try {
            String encryptedBase64Response = EncryptionUtils.getInstance().FixBadRequestTransportChar(response.getResult());
            response.setResult( encryptionController.AESdecrypt(encryptedBase64Response, base64AESKey) );
        } catch (Exception ex) {
            response = new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error: " + ex.toString()+ ", al desencriptar la respuesta del servicio --- respuesta plana: " + response.getResult());
        }

        return response; 
    }
    
    public void loadCustomRSAKeysFromResources(String RSA_publicServiceKeyPath, String RSA_privateClientKeyPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{
        this.CUSTOM_RSA_PUBLIC_SERVICE_KEY = this.rsaCustom.readPublicKey(RSA_publicServiceKeyPath);
        this.CUSTOM_RSA_PRIVATE_CLIENT_KEY = this.rsaCustom.readPrivateKey(RSA_privateClientKeyPath);
    }
    
    public RequestResponse doSecureRequestWithCustomRSA(String requestUrl, String httpMethod, HashMap<String,String> secureParameters, HashMap<String,String> rawParameters, boolean ignoreSSL){
        
        HashMap<String,String> requestParameters = new HashMap();
        
        try {
            //RSA encrypt parameters
            for (Map.Entry<String, String> mapEntry : secureParameters.entrySet()) {
                requestParameters.put(mapEntry.getKey(), this.rsaCustom.encrypt(mapEntry.getValue()));
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error al encriptar los parametros de la peticion - " + ex.getMessage());
        }
        
        if(rawParameters != null){
            requestParameters.putAll(rawParameters);
        }
        
        RequestResponse response = doRequest(requestUrl, httpMethod, "application/x-www-form-urlencoded;charset=UTF-8", requestParameters);
        if(response.getCode() == RequestResponse.RESPONSE_CODE.ERROR){
            return response;
        }
        
        try {
            String encryptedBase64Response = EncryptionUtils.getInstance().FixBadRequestTransportChar(response.getResult());
            response.setResult( this.rsaCustom.decrypt(encryptedBase64Response) );
        } catch (Exception ex) {
            response = new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error: " + ex.toString()+ ", al desencriptar la respuesta del servicio --- respuesta plana: " + response.getResult());
        }

        return response; 
    }
    
    public RequestResponse doPOST(String requestUrl, HashMap<String,String> parameters){
        return doRequest(requestUrl, "POST", "application/x-www-form-urlencoded;charset=UTF-8", parameters);
    } 
    
    public RequestResponse doPOST(String requestUrl, HashMap<String,String> parameters, boolean ignoreSSL){
        return doRequest(requestUrl, "POST", "application/x-www-form-urlencoded;charset=UTF-8", parameters, ignoreSSL);
    } 

    public RequestResponse doGET(String requestUrl, HashMap<String,String> parameters){
        return doRequest(requestUrl, "POST", "application/x-www-form-urlencoded;charset=UTF-8", parameters);
    } 
    
    public RequestResponse doGET(String requestUrl, HashMap<String,String> parameters, boolean ignoreSSL){
        return doRequest(requestUrl, "POST", "application/x-www-form-urlencoded;charset=UTF-8", parameters, ignoreSSL);
    } 
    
    public RequestResponse doRequest(String requestUrl, String httpMethod, String contentType, HashMap<String,String> parameters){
        return doRequest(requestUrl, httpMethod, contentType, parameters, false);
    }
    
    public RequestResponse doRequest(String requestUrl, String httpMethod, String contentType, HashMap<String,String> parameters, boolean ignoreSSL){
        //do request
        boolean isHTTPSRequest = requestUrl.startsWith("https://");
        RequestResponse response;
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
            String plainResponse = RESTServiceUtils.RESTRequest(requestUrl, httpMethod, "application/x-www-form-urlencoded;charset=UTF-8", parameters);
            response = new RequestResponse(RequestResponse.RESPONSE_CODE.SUCCESS, plainResponse);
        } catch (Exception ex) {
            response = new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error en el consumo de la peticion - " + ex.toString());
        }
        
        System.setProperty("https.protocols", httpsProtocols);
        
        return response;
    }    
}
