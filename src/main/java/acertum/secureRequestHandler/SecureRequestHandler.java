package acertum.secureRequestHandler;

import acertum.secureRequestHandler.controllers.EncryptionController;
import acertum.secureRequestHandler.entities.RequestParameters;
import acertum.secureRequestHandler.entities.ServiceResponse;
import acertum.secureRequestHandler.utils.JSONUtils;
import acertum.secureRequestHandler.utils.RESTServiceUtils;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.util.HashMap;

public class SecureRequestHandler {

    public static SecureRequestHandler getInstance(){
        return INSTANCE;
    }
        
    private static final SecureRequestHandler INSTANCE = new SecureRequestHandler();
    private JSONUtils jsonutils;
    private final String URL_UNIQUECODE_SERVICE = "https://10.51.144.40:8443/CodesGeneratorService/webresources/UniqueCodeGeneratorService";
    
    private SecureRequestHandler(){
        jsonutils = JSONUtils.getInstance(); 
    }    
    
    public void requestBarCode(int folio, int sucursal){
        RequestParameters parameters = new RequestParameters(folio, sucursal);
        try {
            EncryptionController encryptionController = new EncryptionController();
            //AES ecrypt content 
            final String encryptedBase64Content = encryptionController.AESencrypt(jsonutils.<RequestParameters>ObjectToJSON(parameters));
            
            //RSA encrypt AESkey
            String base64AESKey = encryptionController.GetAESKeyAsBase64();
            final String encryptedBase64AESKey = encryptionController.RSAencrypt(base64AESKey);
            
            final HashMap serviceParameters = new HashMap<String, String>(){{ 
                put("encryptedContent", encryptedBase64Content); 
                put("transportKey", encryptedBase64AESKey); 
            }};
            String encryptedbase64Response = RESTServiceUtils.postREST(this.URL_UNIQUECODE_SERVICE, serviceParameters);
            //decrypt content with previous AES key
            final String decryptedResponse = encryptionController.AESdecrypt(encryptedbase64Response);
            ServiceResponse response = jsonutils.JSONToObject(decryptedResponse, ServiceResponse.class);
            System.out.println("Decrypted Result: " + response.getResult());
            
            //resultCode = 200;
            //resultContent = Base64.encode(encryptedContent);            
        } catch (Exception ex) {
            //TODO: set error response
            System.err.println("Error: " + ex.toString());
        }
    }        
}
