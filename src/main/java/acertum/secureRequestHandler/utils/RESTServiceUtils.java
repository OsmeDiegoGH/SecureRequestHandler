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

public class RESTServiceUtils {

    public static String RESTRequest(String url, String httplMethod, HashMap<String, String> params) {
        String responseJSON = "";

        try {
            // Init
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

        } catch (IOException e) {
            e.printStackTrace();
            
        }

        return responseJSON;
    }

    public static String getREST(String urlServicio) {

        String respuestaServicio;

        try {
            if (urlServicio.startsWith("https://")) {
                ignoreSSL();
            }

            URL url;
            HttpURLConnection conn;
            url = new URL(urlServicio);

            conn = (HttpURLConnection) url.openConnection();

            //Genero la conexión
            conn.setDoOutput(true);
            conn.setDoInput(true);
            //Método de consumo
            conn.setRequestMethod("GET");
            //Encabezado para el envío de parámetros
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8");
            conn.connect();

            InputStreamReader reader = new InputStreamReader(conn.getInputStream());
            BufferedReader br = new BufferedReader(reader);
            StringBuilder input = new StringBuilder();
            String aux;

            aux = br.readLine();
            while (aux != null) {
                input.append(aux);
//                input = input + aux;
                aux = br.readLine();
            }

            respuestaServicio = input.toString();

        } catch (IOException e) {
            System.out.println("Error al consumir servicio de BD: " + e.getMessage());
            respuestaServicio = "Error al consumir el servicio de BD: " + e.getMessage();
        }

        return respuestaServicio;
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

    public static String getREST(String url, HashMap<String, String> params) {
        return RESTRequest(url, "GET", params);
    }

    public static String postREST(String url, HashMap<String, String> params) {
        return RESTRequest(url, "POST", params);
    }
}
