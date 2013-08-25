/*
 * Copyright 2013 Sosnoski Software Associates Ltd
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.sosnoski.certs;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Make a secure connection, using the certificate in a truststore to verify the server certificate. The truststore
 * certificate may be used directly by the server, or it may be a signing certificate used to endorse the server
 * certificate. You can create the truststore/keystore using a tool such as Portecle (http://portecle.sourceforge.net/),
 * or just run the {@link GetCert} program to build it directly from a server's certificate.
 */
public class UseCert
{
    /**
     * Connect to a server using the certificate in a truststore to verify the server certificate. To keep things simple
     * this always uses the same truststore name, truststore password, and certificate alias (from {@link Constants}).
     * The argument is the target URL.
     *
     * @param args
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        if (args.length == 0) {
            System.out.println("Usage: java com.sosnoski.certs.UseCert url");
            System.exit(1);
        }
        
        // enable debugging to watch connection establishment
        System.setProperty("javax.net.debug", "ssl,handshake");
        
        // open the keystore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream(Constants.TRUSTSTORE_NAME);
        keyStore.load(fis, Constants.TRUSTSTORE_PASS.toCharArray());
        
        // create trust manager that trusts only the server certificate
        String alg = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmfact = TrustManagerFactory.getInstance(alg);
        tmfact.init(keyStore);
        X509TrustManager tm = (X509TrustManager)tmfact.getTrustManagers()[0];
        
        // create the connection (and make sure its secured)
        URL url = new URL(args[0]);
        HttpURLConnection conn = (HttpURLConnection)url.openConnection();
        if (!(conn instanceof HttpsURLConnection)) {
            System.err.println("Connection is not secured!");
        }
        
        // configure SSL connection to use our trust manager
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[] { tm }, null);
        SSLSocketFactory sockfactory = context.getSocketFactory();
        ((HttpsURLConnection)conn).setSSLSocketFactory(sockfactory);
        
        // open connection to the server
        conn.connect();
        conn.getInputStream();
        System.out.println("Got connection to server!");
    }
}
