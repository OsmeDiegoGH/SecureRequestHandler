package acertum.secureRequestHandler.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ArrayUtils {
    
    private static ArrayUtils INSTANCE = new ArrayUtils();
    
    private ArrayUtils(){
    }
    
    public static ArrayUtils getInstance(){
        return INSTANCE;
    }
    
    public byte[] inputStreamToByteArray(InputStream in) throws IOException{
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[16384];

        while ((nRead = in.read(data, 0, data.length)) != -1){
            buffer.write(data, 0, nRead);
        }
        try {
            buffer.flush();
        } catch (IOException ex) {
            System.out.println("WARNING: Unable to flush stream content:" + in.toString());
        }
        
        return buffer.toByteArray();       
    }

}
