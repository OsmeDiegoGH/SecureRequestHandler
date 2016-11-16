package acertum.secureRequestHandler.utils;

public class StringUtils {
    
    private static StringUtils INSTANCE = new StringUtils();
    
    private StringUtils(){
    }
    
    public static StringUtils getInstance(){
        return INSTANCE;
    }
    
    public boolean isNullOrEmpty(String str)
    {
       return str == null || str.isEmpty();
    }
}
