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

package com.sosnoski.tls;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

/**
 * Use a wrapped socket factory to force particular protocol version(s) for a connection.
 */
public class ForceTls
{
    /**
     * Connect to a server using particular protocol version(s). The protocol is controlled by using a wrapper for the
     * {@link SSLSocketFactory} returned by a {@link SSLContext}. The argument is the target URL.
     *
     * @param args
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        if (args.length == 0) {
            System.out.println("Usage: java com.sosnoski.tls.ForceTls url");
            System.exit(1);
        }
        
        // enable debugging to watch connection establishment
        System.setProperty("javax.net.debug", "ssl,handshake");
        
        // create the connection (and make sure its secured)
        URL url = new URL(args[0]);
        HttpURLConnection conn = (HttpURLConnection)url.openConnection();
        if (!(conn instanceof HttpsURLConnection)) {
            System.err.println("Connection is not secured!");
        }
        
        // configure SSL connection to use specific TLS version
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, null, null);
        SSLSocketFactory factory = context.getSocketFactory();
        SSLSocketFactoryWrapper wrapper = new SSLSocketFactoryWrapper(factory, new String[] { "TLSv1.1" }, null);
        ((HttpsURLConnection)conn).setSSLSocketFactory(wrapper);
        
        // open connection to the server
        conn.connect();
        conn.getInputStream();
        System.out.println("Got connection to server!");
    }
}
