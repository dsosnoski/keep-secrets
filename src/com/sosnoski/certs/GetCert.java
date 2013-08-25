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

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;

import javax.net.ssl.HttpsURLConnection;

/**
 * Make a secure connection, saving the certificate used by the server to a truststore.
 */
public class GetCert
{
    /**
     * Save the certificate used by the server to a truststore. To keep things simple this always uses the same
     * truststore name, truststore password, and certificate alias (from {@link Constants}). The argument is the target
     * URL.
     *
     * @param args
     * @throws IOException 
     * @throws GeneralSecurityException 
     */
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        if (args.length == 0) {
            System.out.println("Usage: java com.sosnoski.certs.GetCert url");
            System.exit(1);
        }
        
        // create secure connection to target URL
        URL url = new URL(args[0]);
        HttpURLConnection conn = (HttpURLConnection)url.openConnection();
        if (!(conn instanceof HttpsURLConnection)) {
            System.err.println("Connection is not secured!");
        }
        conn.connect();
        
        // save server certificate to truststore
        Certificate[] certs = ((HttpsURLConnection)conn).getServerCertificates();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null);
        keyStore.setCertificateEntry(Constants.CERTIFICATE_ALIAS, certs[0]);
        FileOutputStream fos = new FileOutputStream(Constants.TRUSTSTORE_NAME);
        keyStore.store(fos, Constants.TRUSTSTORE_PASS.toCharArray());
        System.out.println("Saved certificate for " + url.getHost());
    }
}
