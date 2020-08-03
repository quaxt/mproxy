package com.quaxt.tcpproxy;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.net.URI;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;

public class TlsUtils {

    public static KeyStore loadKeyStore(String keyStoreUrl, String type, char[] pass) {
        URI uri = URI.create(keyStoreUrl);
        Path keyStorePath = Paths.get(uri);
        try (InputStream in = Files.newInputStream(keyStorePath)) {
            KeyStore ks = KeyStore.getInstance(type);
            ks.load(in, pass);
            return ks;
        } catch (KeyStoreException | NoSuchAlgorithmException | IOException
                 | CertificateException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static SSLContext createSSLContext (KeyStore trustStore, KeyStore keyStore,
                             char[] keyStorePassword) {
        try  {
            String algorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
            tmf.init(trustStore);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
            kmf.init(keyStore, keyStorePassword);
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
            return sslContext;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException
                 | KeyManagementException ex) {
            throw new RuntimeException(ex);
        }
    }
}
