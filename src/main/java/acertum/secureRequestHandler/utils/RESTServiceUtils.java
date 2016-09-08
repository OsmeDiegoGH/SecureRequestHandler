package acertum.secureRequestHandler.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
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
import javax.xml.ws.http.HTTPException;

public class RESTServiceUtils {

    public static String RESTRequest(String url, String httplMethod, HashMap<String, String> params) throws IOException, HTTPException {
        String responseJSON = "";
        
        if (url.startsWith("https://")) {
            ignoreSSL();
        }

        URL u = new URL(url);
        HttpURLConnection con = (HttpURLConnection) u.openConnection();

        con.setDoOutput(true);
        con.setDoInput(true);
        con.setRequestMethod(httplMethod);
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8");

        //Parse params
        String paramsParsed = "";
        for (Entry<String, String> tmp : params.entrySet()) {
            paramsParsed += tmp.getKey() + "=" + tmp.getValue() + "&";
        }

        if (paramsParsed.endsWith("&")) {
            paramsParsed = paramsParsed.substring(0, paramsParsed.length() - 1);
        }

        OutputStream os = con.getOutputStream();
        OutputStreamWriter ow = new OutputStreamWriter(os);
        ow.write(paramsParsed);
        ow.flush();
        ow.close();
        os.close();

        // Response
        InputStream is = con.getInputStream();
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

    private static void ignoreSSL() {
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

    public static String getREST(String url, HashMap<String, String> params) throws IOException, HTTPException {
        return RESTRequest(url, "GET", params);
    }

    public static String postREST(String url, HashMap<String, String> params) throws IOException, HTTPException {
        return RESTRequest(url, "POST", params);
    }
}
