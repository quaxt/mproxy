package com.quaxt.tcpproxy;
import java.io.*;
import java.lang.invoke.MethodHandles;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyStore;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ServerSocketFactory;
import javax.net.ssl.*;
import javax.net.ssl.SSLSocket;

public enum MProxy {
    INSTANCE;

    /**
       Reads content from inSocket and writes it to outSocket until in.read() returns -1.
    */
    public void transferBytes(Socket inSocket,
                              Socket outSocket) {
        new Thread(() -> {
                try (InputStream in = inSocket.getInputStream();
                     OutputStream out = outSocket.getOutputStream();
                     ReadableByteChannel inChannel = Channels.newChannel(in);
                     WritableByteChannel outChannel = Channels.newChannel(out);) {
                    ByteBuffer buffer = ByteBuffer.allocate(4096);
                    int bytesRead;
                    while ((bytesRead = inChannel.read(buffer)) != -1) {
                        buffer.flip();
                        if (bytesRead != 0) {
                            while(buffer.hasRemaining()) {
                                outChannel.write(buffer);
                            }
                        }
                    }
                    System.out.println("Done");
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
        }).start();
    }

    private final int readFully(InputStream in, byte[] b, int off, int len) throws IOException {
        int n = 0;
        while (n < len) {
            int count = in.read(b, off + n, len - n);
            if (count < 0) {
                break;
            }
            n += count;
        }
        return n;
    }

/**
read a packet return the bytes of the packet including header and
content
*/
    public byte[] readPacket(InputStream mysqlInput) throws IOException {
        byte[] header = new byte[4];
        int lengthRead = readFully(mysqlInput, header, 0, 4);
        int packetLength = (header[0] & 0xff)
            + ((header[1] & 0xff) << 8)
            + ((header[2] & 0xff) << 16);
        // Read data
        byte[] buffer = new byte[packetLength + 4];
        System.arraycopy(header, 0, buffer, 0, 4);
        int numBytesRead = readFully(mysqlInput, buffer, 4, packetLength);
        if (numBytesRead != packetLength) {
            throw new IOException("Short read, expected " + packetLength + " bytes, only read " + numBytesRead);
        }
        return buffer;
    }

    public void startTransfer(Socket inSocket, Socket outSocket) {
        /* In each case, whether in is the route to the server
        or to the db client, the first packet is special because it is
        unencrypted */
        try  {
            InputStream in = inSocket.getInputStream();
            OutputStream out = outSocket.getOutputStream();
            WritableByteChannel outChannel = Channels.newChannel(out);
            byte[] packet = readPacket(in);
            outChannel.write(ByteBuffer.wrap(packet));
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public SSLSocket convertSocketToSsl (Socket socket, SSLContext sslContext)
    throws IOException {
        SSLSocketFactory sslSf = sslContext.getSocketFactory();
        return (SSLSocket) sslSf.createSocket(socket, null, socket.getPort(), false);
    }


    public void setSSLParameters(SSLSocket sslSocket, boolean requireClientAuth, String serverName) {
         SSLParameters p = sslSocket.getSSLParameters();
         p.setNeedClientAuth(requireClientAuth);
         if (serverName != null) {
             p.setServerNames(Arrays.asList(new SNIHostName(serverName)));
         }
         sslSocket.setSSLParameters(p);
    }

    public void handleConnect(Socket client,
                              String remoteServerName,
                              SocketAddress remoteAddress,
                              SSLContext sslContextToServer,
                              boolean clientAuthenticationToServer,
                              boolean clientAuthenticationToProxy) {
        try {
            Socket server = new Socket();
            server.connect(remoteAddress);
            startTransfer(server, client);
            startTransfer(client, server);
            client = convertSocketToSsl(client, sslContext);
            server = convertSocketToSsl(server, sslContext);
            System.out.println("clientAuthenticationToServer=" + clientAuthenticationToServer);
            setSSLParameters((SSLSocket)server, clientAuthenticationToServer, remoteServerName);
            setSSLParameters((SSLSocket)client, clientAuthenticationToProxy, null);
            ((SSLSocket)server).startHandshake();
            ((SSLSocket)client).setUseClientMode(false);
            transferBytes(client, server);
            transferBytes(server, client);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static SSLContext createSSLContext (Properties p) {
        String trustStoreUrl =
            p.getProperty("trustStoreUrl");
        KeyStore trustStore = null;
        char[] trustStorePassword;
        if (trustStoreUrl != null) {
            trustStorePassword = p.getProperty("trustStorePassword").toCharArray();
            String trustStoreType = p.getProperty("trustStoreType");
            trustStore = TlsUtils.loadKeyStore(trustStoreUrl,
                                                             trustStoreType,
                                                             trustStorePassword);
        }
        String keyStoreUrl =
            p.getProperty("keyStoreUrl");
        KeyStore keyStore = null;
        char[] keyStorePassword = null;
        if (keyStoreUrl != null) {
            keyStorePassword = p.getProperty("keyStorePassword").toCharArray();
            String keyStoreType = p.getProperty("keyStoreType");
            keyStore = TlsUtils.loadKeyStore(keyStoreUrl,
                                                             keyStoreType,
                                                             keyStorePassword);
        }
        return TlsUtils.createSSLContext(trustStore,
                                         keyStore,
                                         keyStorePassword);
    }

    public void listen(SocketAddress localAddress,
                       String remoteHost,
                       SocketAddress remoteAddress,
                       SSLContext sslContext,
                       boolean clientAuthenticationToServer,
                       boolean clientAuthenticationToProxy) {
        System.out.println("localAddress = " + localAddress);
        System.out.println("remoteAddress = " + remoteAddress);
        try {
            ServerSocket serverSocket = new ServerSocket();
            serverSocket.bind(localAddress);
            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("connect");
                handleConnect(socket, remoteHost, remoteAddress, sslContext,
                              clientAuthenticationToServer, clientAuthenticationToProxy);
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public static void usage () {
        System.out.println("Usage: java " + MethodHandles.lookup().lookupClass().getCanonicalName() + " -config <configFile>");
    }

    public static Properties getProperties (Path propertiesFile) {
        Properties p = new Properties();
        try (InputStream in = Files.newInputStream(propertiesFile)) {
            p.load(in);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return p;
    }

    public void launch(Properties p) {
        SSLContext sslContext = createSSLContext(p);
        String remoteHost = p.getProperty("remoteHost");
        int remotePort = Integer.parseInt(p.getProperty("remotePort"));
        int port = Integer.parseInt(p.getProperty("port"));
        boolean clientAuthenticationToServer = Boolean.parseBoolean(p.getProperty("clientAuthenticationToServer"));
        boolean clientAuthenticationToProxy = Boolean.parseBoolean(p.getProperty("clientAuthenticationToProxy"));
        SocketAddress remoteAddress =
            new InetSocketAddress(remoteHost, remotePort);
        SocketAddress localAddress = new InetSocketAddress(port);
        listen(localAddress, remoteHost, remoteAddress, sslContext,
               clientAuthenticationToServer, clientAuthenticationToProxy);
    }

    public static void main (String[] args) {
        if (args.length != 2 || ! "-config".equals(args[0])) {
            usage();
            System.exit(-1);
        }
        Properties p = getProperties(Paths.get(args[1]));
        INSTANCE.launch(p);
    }

}
