package com.wisekey.openidconnect;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

public class RestWrapper {

    /**
     * 
     */
    public KeyStore LoadJksCert(String path, String password) 
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        
        // Get certificate in file
        KeyStore keyStore = KeyStore.getInstance("jks");
        FileInputStream inputCert = new FileInputStream(path);
        
        // Load certificate
        keyStore.load(inputCert, password.toCharArray());
        return keyStore;
    }
    
    /**
     * 
     */
    public RestTemplate createTemplate(KeyStore clientCertificate, String password) 
            throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        RestTemplate restTemplate = new RestTemplate();
        
        if (clientCertificate != null) {
            
            HttpComponentsClientHttpRequestFactory requestFactory = null;
            SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(new SSLContextBuilder()
                    .loadTrustMaterial(null, new TrustSelfSignedStrategy())
                    .loadKeyMaterial(clientCertificate, password.toCharArray()).build(),
                        NoopHostnameVerifier.INSTANCE);

            HttpClient httpClient = HttpClients.custom().setSSLSocketFactory(socketFactory)
                    .setMaxConnTotal(5)
                    .setMaxConnPerRoute(5)
                    .build();
      
            requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
            requestFactory.setReadTimeout(10000);
            requestFactory.setConnectTimeout(10000);

            restTemplate.setRequestFactory(requestFactory);
        }
        
        return restTemplate;
    }
    
    /**
     * 
     */
    public String request(RestTemplate restTemplate, String uri, HttpMethod method,  HttpEntity<?> entity) {
        ResponseEntity<String> response;
        response = restTemplate.exchange(uri, method, entity, String.class);
        String strBody = response.getBody();
        return strBody;
        
    }    
}