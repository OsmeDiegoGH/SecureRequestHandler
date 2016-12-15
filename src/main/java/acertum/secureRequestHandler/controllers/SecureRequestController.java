package acertum.secureRequestHandler.controllers;

import acertum.secureRequestHandler.entities.RequestResponse;
import acertum.secureRequestHandler.handlers.DefaultEncryptorHandler;
import acertum.secureRequestHandler.utils.RESTServiceUtils;
import acertum.secureRequestHandler.handlers.IRequestHandler;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SecureRequestController<T extends IRequestHandler>{
    
    private final T encryptorHandler;
    public boolean debug = false;
    
    public SecureRequestController(Class<?> callerClass){
        this((T) new DefaultEncryptorHandler(callerClass));
        com.sun.org.apache.xml.internal.security.Init.init();
    }
  
    public SecureRequestController(T encryptorHandler){
        this.encryptorHandler = encryptorHandler;
    }
     
    public T getHandler(){
        return this.encryptorHandler;
    }
    
    public RequestResponse doSecurePOST(String requestUrl, String contentType, HashMap<String,String> secureParameters){
        return doSecureRequest(requestUrl, "POST", contentType, secureParameters, new HashMap<String, String>(), false);
    } 
    
    public RequestResponse doSecurePOST(String requestUrl, String contentType, HashMap<String,String> secureParameters, boolean ignoreSSL){
        return doSecureRequest(requestUrl, "POST", contentType, secureParameters, new HashMap<String, String>(), ignoreSSL);
    } 
    
    public RequestResponse doSecurePOST(String requestUrl, String contentType, HashMap<String,String> secureParameters, HashMap<String,String> rawParameters){
        return doSecureRequest(requestUrl, "POST", contentType, secureParameters, rawParameters, false);
    } 
    
    public RequestResponse doSecurePOST(String requestUrl, String contentType, HashMap<String,String> secureParameters, HashMap<String,String> rawParameters, boolean ignoreSSL){
        return doSecureRequest(requestUrl, "POST", contentType, secureParameters, rawParameters, ignoreSSL);
    } 

    public RequestResponse doSecureGET(String requestUrl, String contentType, HashMap<String,String> secureParameters){
        return doSecureRequest(requestUrl, "GET", contentType, secureParameters, new HashMap<String, String>(), false);
    } 
    
    public RequestResponse doSecureGET(String requestUrl, String contentType, HashMap<String,String> secureParameters, boolean ignoreSSL){
        return doSecureRequest(requestUrl, "GET", contentType, secureParameters, new HashMap<String, String>(), ignoreSSL);
    } 
    
    public RequestResponse doSecureGET(String requestUrl, String contentType, HashMap<String,String> secureParameters, HashMap<String,String> rawParameters){
        return doSecureRequest(requestUrl, "GET", contentType, secureParameters, rawParameters, false);
    }  
    
    public RequestResponse doSecureGET(String requestUrl, String contentType, HashMap<String,String> secureParameters, HashMap<String,String> rawParameters, boolean ignoreSSL){
        return doSecureRequest(requestUrl, "GET", contentType, secureParameters, rawParameters, ignoreSSL);
    }  

    public RequestResponse doSecureRequest(String requestUrl, String httpMethod, String contentType, HashMap<String,String> secureParameters, HashMap<String,String> rawParameters, boolean ignoreSSL){
        try {
            this.encryptorHandler.prepare(requestUrl, httpMethod, contentType, secureParameters, rawParameters);
        } catch (Exception ex) {
            if(debug){
                ex.printStackTrace();
            }
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error preparing request: " + ex.getMessage());
        }
                
        HashMap requestParameters = new HashMap<String,String>();
        requestParameters.putAll(rawParameters);
        
        try {
            for (Map.Entry<String, String> mapEntry : secureParameters.entrySet()) {
                requestParameters.put(mapEntry.getKey(), this.encryptorHandler.encrypt((String)mapEntry.getValue()));
            } 
        } catch (Exception ex) {
            if(debug){
                ex.printStackTrace();
            }
            return new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error encrypting parameters: " + ex.getMessage());
        }
        
        RequestResponse response = doRequest(requestUrl, httpMethod, contentType, requestParameters, ignoreSSL);
        if(response.getCode() == RequestResponse.RESPONSE_CODE.ERROR){
            return response;
        }
        
        try {
            response.setResult( this.encryptorHandler.decrypt(response.getResult()) );
        } catch (Exception ex) {
            if(debug){
                ex.printStackTrace();
            }
            response = new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error: " + ex.toString()+ ", al desencriptar la respuesta del servicio --- respuesta plana: " + response.getResult());
        }
    
        return response; 
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
            String plainResponse = RESTServiceUtils.RESTRequest(requestUrl, httpMethod, contentType, parameters);
            response = new RequestResponse(RequestResponse.RESPONSE_CODE.SUCCESS, plainResponse);
        } catch (Exception ex) {
            if(debug){
                ex.printStackTrace();
            }
            response = new RequestResponse(RequestResponse.RESPONSE_CODE.ERROR, "Error en el consumo de la peticion - " + ex.toString());
        }
        
        System.setProperty("https.protocols", httpsProtocols);
        
        return response;
    }  
}
