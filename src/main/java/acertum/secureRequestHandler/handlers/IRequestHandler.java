package acertum.secureRequestHandler.handlers;

import java.util.HashMap;

public interface IRequestHandler {
    /* TODO: verify how can be preserved method names in parameters */
    public void prepare(String requestUrl, String httpMethod, String contentType, HashMap<String,String> secureParameters, HashMap<String,String> rawParameters) throws Exception;
    public String encrypt(String rawParameter) throws Exception;
    public String decrypt(String rawParameter) throws Exception;
}
