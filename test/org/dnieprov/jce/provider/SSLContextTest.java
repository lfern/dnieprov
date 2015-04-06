/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.dnieprov.jce.provider;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author luis
 */
public class SSLContextTest {
    
    public SSLContextTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
        Provider p = new DnieProvider();
        Security.insertProviderAt(p, 1);
    }
    
    @After
    public void tearDown() {
    }

    
      
    
      
    
    @Test
    public void testSSLContextMSCapi() throws Exception{
        try {
            KeyStore ks = KeyStore.getInstance("Windows-MY");
            ks.load(null, null);
            
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, "".toCharArray());
            
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            
            X509KeyManager km = null;
            KeyManager[]k = kmf.getKeyManagers();
            for (int i=0;i<k.length;i++){
                if (k[i] instanceof X509KeyManager){
                    km = (X509KeyManager)k[i];
                    break;
                }
            }
            FixedAliasKeyManager fkm = new FixedAliasKeyManager(km,Defaults.aliasMy);
            
            TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            
            tmf.init(ks);
            X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            AllTrustManager tm = new AllTrustManager(defaultTrustManager);            
            
            
            sslContext.init(new KeyManager[]{fkm},new TrustManager[]{tm},null);
            
            SSLSocketFactory factory=sslContext.getSocketFactory();
            SSLSocket socket=(SSLSocket)factory.createSocket(Defaults.testIP,443);
            socket.setUseClientMode(true);
            socket.startHandshake();
            
            
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
            out.println("GET / HTTP/1.0");
            out.println();
            out.flush();

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
              System.out.println(inputLine);
            }
             in.close();

             out.close();
             socket.close();            
        } catch (Exception ex){
            ex.printStackTrace();
        }
    }  
    
    @Test
    public void testSSLContextDnieProv() throws Exception{
        try {
            //System.setProperty("javax.net.debug", "ALL");
            KeyStore ks3 = KeyStore.getInstance("Windows-ROOT");
            ks3.load(null, null);
            
            KeyStore ks = KeyStore.getInstance("DNIe");
            ks.load(null,null);
/*
            Enumeration<String> enu = ks.aliases();
            while (enu.hasMoreElements()){
                System.out.println(enu.nextElement());
            }
*/
            
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, "".toCharArray());
            
            //System.setProperty("https.protocols", "TLSv1");
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            
            X509KeyManager km = null;
            KeyManager[]k = kmf.getKeyManagers();
            for (int i=0;i<k.length;i++){
                if (k[i] instanceof X509KeyManager){
                    km = (X509KeyManager)k[i];
                    break;
                }
            }
            FixedAliasKeyManager fkm = new FixedAliasKeyManager2(km,Defaults.aliasDnie,ks3);
            
            TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            
            tmf.init(ks);
            X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            AllTrustManager tm = new AllTrustManager(defaultTrustManager);            

            //sslContext.init(kmf.getKeyManagers(),null,null);
            sslContext.init(new KeyManager[]{fkm},new TrustManager[]{tm},null);
            
            SSLSocketFactory factory=sslContext.getSocketFactory();
            SSLSocket socket=(SSLSocket)factory.createSocket(Defaults.testIP,443);
            socket.setUseClientMode(true);
            socket.startHandshake();
            
            
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
            out.println("GET / HTTP/1.0");
            out.println();
            out.flush();
/*            
            HttpServletResponse response;
            if (out.checkError()) {
               response.getWriter().println("Error durring request sending");
            }
*/
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
              System.out.println(inputLine);//response.getWriter().println(inputLine);
            }
             in.close();

             out.close();
             socket.close();            
        } catch (Exception ex){
            ex.printStackTrace();
        }
     
        fail("The test case is a prototype.");
    }    
    
}