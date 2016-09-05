package acertum.secureRequestHandler.utils;

import com.google.gson.Gson;

public class JSONUtils {
    
    private final static JSONUtils INSTANCE = new JSONUtils();
    
    private JSONUtils(){
    }
    
    public static JSONUtils getInstance(){
        return INSTANCE;
    }
    
    public <T> T JSONToObject(String json,  Class<T> classType){
        return new Gson().fromJson(json, classType);
    }
    
    public <T> String ObjectToJSON(T obj) throws Exception {
        return new Gson().toJson(obj);
    }
}
