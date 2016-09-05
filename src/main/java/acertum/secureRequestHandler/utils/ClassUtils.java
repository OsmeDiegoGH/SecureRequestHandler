package acertum.secureRequestHandler.utils;

import java.lang.reflect.Method;

public class ClassUtils {
    
    public <T> Method[] getPublicClassMethods(Class<T> classType){
        return classType.getClass().getDeclaredMethods();
    }
    
}
