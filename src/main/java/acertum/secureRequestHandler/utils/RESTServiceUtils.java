package acertum.secureRequestHandler.utils;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map.Entry;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.InetAddress; 
import java.net.NetworkInterface; 
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;


public class RESTServiceUtils {
    
    private static final int CONNECTION_TIMEOUT = 1000;
    private static final StringUtils stringUtils = StringUtils.getInstance();

    public static String RESTRequest(String url, String httplMethod, String contentType, HashMap<String, String> params) throws Exception {
        String responseJSON = "";
        
        URL u = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setConnectTimeout(CONNECTION_TIMEOUT);

        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setRequestMethod(httplMethod);
        conn.setRequestProperty("Content-Type", contentType);
        
        String clientIP = getClientIP();
        if(!stringUtils.isNullOrEmpty(clientIP)){
            conn.setRequestProperty("X-IP-ORIGEN", clientIP);
        }
        
        //Parse params
        String paramsParsed = "";
        for (Entry<String, String> tmp : params.entrySet()) {
            paramsParsed += tmp.getKey() + "=" + URLEncoder.encode(tmp.getValue(), "UTF-8") + "&";
        }

        if (paramsParsed.endsWith("&")) {
            paramsParsed = paramsParsed.substring(0, paramsParsed.length() - 1);
        }

        OutputStream os = conn.getOutputStream();
        OutputStreamWriter ow = new OutputStreamWriter(os);
        ow.write(paramsParsed);
        ow.flush();
        ow.close();
        os.close();

        // Response
        InputStream is = conn.getInputStream();
        InputStreamReader ir = new InputStreamReader(is);
        BufferedReader br = new BufferedReader(ir);

        String jsonPart;
        while ((jsonPart = br.readLine()) != null) {
            responseJSON = responseJSON + jsonPart;
        }

        ir.close();
        is.close();

        return responseJSON;
    }

    public static void ignoreSSL() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                @Override
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }};

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            HostnameVerifier allHostsValid = new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };

            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error [UtilWS@ignorarSSL]: " + e.getMessage());
        } catch (KeyManagementException e) {
            System.err.println("Error [UtilWS@ignorarSSL]: " + e.getMessage());
        }
    }
    
     private static String getClientIP() { 
        String ipRequest = null; 
        
        try { 
            
            ipRequest = InetAddress.getLocalHost().getHostAddress(); 
            
            if ( ipRequest.startsWith("127.") ) { 
                /* Go harder! */ 
                
                Enumeration<NetworkInterface> nInterfaces = NetworkInterface.getNetworkInterfaces(); 
                
                while( nInterfaces.hasMoreElements() ) { 
                    
                    Enumeration<InetAddress> inetAddresses = nInterfaces.nextElement().getInetAddresses(); 
                    
                    while ( inetAddresses.hasMoreElements() ) { 
                        ipRequest = inetAddresses.nextElement().getHostAddress(); 
                        
                        if ( !ipRequest.startsWith("127.") ) 
                            return ipRequest; 
                    } 
                } 
            } 
        } catch (UnknownHostException e ) { 
            System.err.println( "[RESTServiceUtils::getClientIP()] Error: " + e.getMessage() ); 
        } catch (SocketException e) { 
            System.err.println( "[RESTServiceUtils::getClientIP()] Error: " + e.getMessage() ); 
        } 
        
        return ipRequest; 
    } 

}
