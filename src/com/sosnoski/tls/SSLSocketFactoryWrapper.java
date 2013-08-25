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
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Wrapper for a secure socket factory which overrides socket parameters on every created socket.
 *
 * @author Dennis M. Sosnoski
 */
public class SSLSocketFactoryWrapper extends SSLSocketFactory
{
    private final SSLSocketFactory wrappedFactory;
    private final String[] enabledProtocols;
    private final String[] enabledSuites;
    
    /**
     * Constructor.
     *
     * @param factory
     * @param protocols
     * @param suites
     */
    public SSLSocketFactoryWrapper(SSLSocketFactory factory, String[] protocols, String[] suites) {
        wrappedFactory = factory;
        enabledProtocols = protocols;
        enabledSuites = suites;
    }

    /**
     * @param host
     * @param port
     * @return
     * @throws IOException
     * @throws UnknownHostException
     * @see javax.net.SocketFactory#createSocket(java.lang.String, int)
     */
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        SSLSocket socket = (SSLSocket)wrappedFactory.createSocket(host, port);
        setParameters(socket);
        return socket;
    }
    
    /**
     * @param host
     * @param port
     * @param localHost
     * @param localPort
     * @return
     * @throws IOException
     * @throws UnknownHostException
     * @see javax.net.SocketFactory#createSocket(java.lang.String, int, java.net.InetAddress, int)
     */
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException,
        UnknownHostException {
        SSLSocket socket = (SSLSocket)wrappedFactory.createSocket(host, port, localHost, localPort);
        setParameters(socket);
        return socket;
    }
    
    /**
     * @param host
     * @param port
     * @return
     * @throws IOException
     * @see javax.net.SocketFactory#createSocket(java.net.InetAddress, int)
     */
    public Socket createSocket(InetAddress host, int port) throws IOException {
        SSLSocket socket = (SSLSocket)wrappedFactory.createSocket(host, port);
        setParameters(socket);
        return socket;
    }
    
    /**
     * @param address
     * @param port
     * @param localAddress
     * @param localPort
     * @return
     * @throws IOException
     * @see javax.net.SocketFactory#createSocket(java.net.InetAddress, int, java.net.InetAddress, int)
     */
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
        throws IOException {
        SSLSocket socket = (SSLSocket)wrappedFactory.createSocket(address, port, localAddress, localPort);
        setParameters(socket);
        return socket;
    }

    /**
     * @return
     * @throws IOException
     * @see javax.net.SocketFactory#createSocket()
     */
    public Socket createSocket() throws IOException {
        SSLSocket socket = (SSLSocket)wrappedFactory.createSocket();
        setParameters(socket);
        return socket;
    }

    /**
     * @return
     * @see javax.net.ssl.SSLSocketFactory#getDefaultCipherSuites()
     */
    public String[] getDefaultCipherSuites() {
        return wrappedFactory.getDefaultCipherSuites();
    }

    /**
     * @return
     * @see javax.net.ssl.SSLSocketFactory#getSupportedCipherSuites()
     */
    public String[] getSupportedCipherSuites() {
        return enabledSuites == null ? wrappedFactory.getSupportedCipherSuites() : enabledSuites;
    }

    /**
     * @param s
     * @param host
     * @param port
     * @param autoClose
     * @return
     * @throws IOException
     * @see javax.net.ssl.SSLSocketFactory#createSocket(java.net.Socket, java.lang.String, int, boolean)
     */
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        SSLSocket socket = (SSLSocket)wrappedFactory.createSocket(s, host, port, autoClose);
        setParameters(socket);
        return socket;
    }
    
    /**
     * Override the configured parameters on the socket.
     *
     * @param socket
     */
    private void setParameters(SSLSocket socket) {
        if (enabledProtocols != null) {
            socket.setEnabledProtocols(enabledProtocols);
        }
        if (enabledSuites != null) {
            socket.setEnabledCipherSuites(enabledSuites);
        }
    }
}