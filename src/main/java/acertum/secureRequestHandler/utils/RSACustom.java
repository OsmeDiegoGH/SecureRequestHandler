package acertum.secureRequestHandler.utils;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.regex.Pattern;

public class RSACustom {
    
    private RSAPrivateKey PRIVATE_KEY; 
    private RSAPublicKey  PUBLIC_KEY;
    private final int CHUNK_LENGTH = 117;
    private final Class CALLER_CLASS;
    
    public RSACustom(Class<?> callerClass){
        this.CALLER_CLASS = callerClass;
    }
    
    public RSAPrivateKey readPrivateKey(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException{
        InputStream inPrivateKey = this.CALLER_CLASS.getResourceAsStream( filename );
        byte[] keyBytes = inputStreamToByteArray( inPrivateKey );
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( keyBytes );
        KeyFactory kf = KeyFactory.getInstance( "RSA" );
        PRIVATE_KEY = (RSAPrivateKey) kf.generatePrivate( spec );
        return PRIVATE_KEY;
    }

    public  RSAPublicKey readPublicKey(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException{
        InputStream inPublicKey = RSACustom.class.getResourceAsStream( filename );
        byte[] keyBytes = inputStreamToByteArray( inPublicKey );
        X509EncodedKeySpec spec = new X509EncodedKeySpec( keyBytes );
        KeyFactory kf = KeyFactory.getInstance( "RSA" );
        PUBLIC_KEY = (RSAPublicKey) kf.generatePublic( spec );
        return PUBLIC_KEY;
    }
    
    private byte[] inputStreamToByteArray(InputStream in){
        
        byte[] bytes = null;
    
        try {
            
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();

            int nRead;
            byte[] data = new byte[16384];

            while ((nRead = in.read(data, 0, data.length)) != -1)
                buffer.write(data, 0, nRead);

            buffer.flush();

            bytes = buffer.toByteArray();
        
        } catch( Exception e ) {
            
            System.err.println("No se pudo abrir el stream de la llave para RSA");
            
        }
        
        return bytes;
    }
    
    private String _encrypt(String msg){
        
        BigInteger n = PUBLIC_KEY.getModulus();
        BigInteger e = PUBLIC_KEY.getPublicExponent();
        
        BigInteger m = new BigInteger( msg.getBytes() );
        
        return m.modPow(e, n).toString();
    }
    
    private String _decrypt(String msg){
        
        BigInteger n = PRIVATE_KEY.getModulus();
        BigInteger d = PRIVATE_KEY.getPrivateExponent();
        
        return new String(
            (new BigInteger(msg)).modPow(d, n).toByteArray()
        );
    }
    
    public String encrypt(String text){
        
        // Calcular trozos
        int sobrantes   = text.length() % CHUNK_LENGTH ;
        int totalTrozos = (text.length() - sobrantes) / CHUNK_LENGTH ;

        ArrayList<String> trozo = new ArrayList();
        
        for(int k = 0; k < totalTrozos; k++)
            trozo.add( text.substring( k * CHUNK_LENGTH , (k+1) * CHUNK_LENGTH ) );
        
        if( sobrantes > 0 )
            trozo.add( text.substring( totalTrozos * CHUNK_LENGTH, text.length() ) );
        
        // Encriptar los trozos
        StringBuilder textFinal = new StringBuilder();
        
        textFinal.append( trozo.size() );
        
        for(int i = 0; i < trozo.size(); i++ ){
            textFinal.append(":");
            textFinal.append( _encrypt( trozo.get( i ) ) );
        }
        
        return textFinal.toString();
    }
    
    public String decrypt(String text){
        // Decodificar trozos
        String[] p      = text.split(":");
        int totalTrozos = Integer.parseInt( p[0] );
        int k = 1;
        
        // Desencriptar los trozos
        StringBuilder textFinal = new StringBuilder();
        
        for( int i = 0; i < totalTrozos; i++ )
            textFinal.append( _decrypt( p[ k++ ] ) );
        
        // Devolver Mensaje Original
        return textFinal.toString();
    }

    public static String[] pipedStringToArray(String pipedString){
        return pipedString.split(Pattern.quote("|"));       
    }
    
    public static String toPipedString(String[] arr){
        String result = "";
        for(int i = 0, total = arr.length; i < total; i++){
            result += arr[i] + "|";
        }
        return result;
    }
    
    public static String getElementFromPipedString(String pipedString, int elementPosition){
        String[] elements = pipedStringToArray(pipedString);
        
        if(elementPosition < elements.length){
            return elements[elementPosition];
        }
        
        return null;
    }
    
    public static void main(String[] argv) throws NoSuchAlgorithmException, InvalidKeySpecException{
        RSACustom self = new RSACustom(RSACustom.class);
        
        self.PRIVATE_KEY = self.readPrivateKey( "/crypto/custom_rsa_private_key_test.der"  );
        self.PUBLIC_KEY = self.readPublicKey ( "/crypto/custom_rsa_public_key_test.der" );    
            
        String plain = "Love is like a never ending melody, Poets have compared it to a symphony, A symphony conducted by the lighting of the moon, But our song of love is slightly out of tune.... Once your kisses raised me to a fever pitch, Now the orchestration doesn't seem so rich, Seems to me you've changed the tune we used to sing, Like the bossa nova love should swing.... We used to harmonize two souls in perfect time, Now the song is different and the words don't even rhyme, ‘Cause you forgot the melody our hearts would always croon, What good's a heart that's slightly out of tune? Tune your heart with mine the way it used to be, Join with me in harmony and sing a song of love, We're bound to get in tune again before too long, There'll be no Desafinado when your heart belongs to me completely Then you won't be slightly out of tune, you'll sing along with me!";
        String encrypted, decrypted;

        System.out.println("Plain:\n    " + plain);

        encrypted = self.encrypt( plain );
        System.out.println("Encrypted:\n    " + encrypted);

        decrypted = self.decrypt( encrypted );
        System.out.println("Decrypted:\n    " + decrypted);
    }
}