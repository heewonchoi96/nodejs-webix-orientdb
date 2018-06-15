package TLS;  

import java.io.BufferedReader;  
import java.io.FileInputStream;  
import java.io.IOException;  
import java.io.InputStream;  
import java.io.InputStreamReader;  
import java.net.URL;  
import java.security.KeyManagementException;  
import java.security.KeyStore;  
import java.security.KeyStoreException;  
import java.security.NoSuchAlgorithmException;  
import java.security.cert.CertificateException;  
import java.security.cert.X509Certificate;  

import javax.net.ssl.HostnameVerifier;  
import javax.net.ssl.HttpsURLConnection;  
import javax.net.ssl.SSLContext;  
import javax.net.ssl.SSLSession;  
import javax.net.ssl.TrustManager;  
import javax.net.ssl.TrustManagerFactory;  
import javax.net.ssl.X509TrustManager;  

/** 
 * SSLContext.init() 함수의 두번째 인자에 X509TrustManager 를 선언하여 집어 넣었다.
 * 그리고 JRE 를 설치하면 기본적으로 [JRE 경로]/lib/security/cacerts 라는 파일명의 공인 인증된 인증서 저장소 파일이 있다.
 * 해당 인증서 저장소를 이용하여 서버의 인증서를 검사하게 하였다.
 */  
public class TLSProtocol {  

	/** 
	 * @param urlString 
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyManagementException 
	 */  
	public void getHttps(String urlString) throws IOException, NoSuchAlgorithmException, KeyManagementException {  

		// Get HTTPS URL connection  
		URL url = new URL(urlString);    
		HttpsURLConnection conn = (HttpsURLConnection)url.openConnection();  

		// Set Hostname verification  
		conn.setHostnameVerifier(new HostnameVerifier() {  
			@Override  
			public boolean verify(String hostname, SSLSession session) {  
				// Ignore host name verification. It always returns true.  
				return true;  
			}  
		});  

		// SSL setting  
		SSLContext context = SSLContext.getInstance("TLSv1.2");  
		context.init(null, new TrustManager[] { new X509TrustManager() { // SSLContext.init() 함수의 두번째 인자에 X509TrustManager 를 선언하여 집어 넣었다.

			@Override  
			public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {  
				// client certification check  
			}  

			@Override  
			public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {  
				// Server certification check  
				try {  

					// Get trust store  
					KeyStore trustStore = KeyStore.getInstance("JKS");  
					// JRE를 설치하면 기본적으로 [JRE 경로]/lib/security/cacerts 라는 파일명의 공인 인증된 인증서 저장소 파일이 있다.
					// 해당 인증서 저장소를 이용하여 서버의 인증서를 검사하게 하였다.
					String cacertPath = System.getProperty("java.home") + "/lib/security/cacerts";
					trustStore.load(new FileInputStream(cacertPath), "changeit".toCharArray()); // Use default certification validation  

					// Get Trust Manager  
					TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());  
					tmf.init(trustStore);  
					TrustManager[] tms = tmf.getTrustManagers();  
					((X509TrustManager)tms[0]).checkServerTrusted(chain, authType);  

				} catch (KeyStoreException e) {  
					e.printStackTrace();  
				} catch (NoSuchAlgorithmException e) {  
					e.printStackTrace();  
				} catch (IOException e) {  
					e.printStackTrace();  
				}  
			}  

			@Override  
			public X509Certificate[] getAcceptedIssuers() {  
				return null;  
			}  
		} }, null);  
		conn.setSSLSocketFactory(context.getSocketFactory());  

		// Connect to host  
		conn.connect();  
		conn.setInstanceFollowRedirects(true);  

		// Print response from host  
		InputStream in = conn.getInputStream();  
		BufferedReader reader = new BufferedReader(new InputStreamReader(in));  
		String line = null;  
		while ((line = reader.readLine()) != null) {  
			System.out.printf("%s\n", line);  
		}  
		reader.close();  
	}  

	/** 
	 * @param args 
	 * @throws Exception 
	 */  
	public static void main(String[] args) throws Exception {  
		TLSProtocol test = new TLSProtocol();  
		test.getHttps("https://www.naver.com/");  
	}  
	
}  