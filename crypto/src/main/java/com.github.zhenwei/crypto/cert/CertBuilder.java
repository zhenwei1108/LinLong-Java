package org.sdk.crypto.cert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
 

import org.sdk.crypto.utils.Base64Util;

public class CertBuilder {


  public static Certificate buildBcCert(String cert) throws IOException {
    ByteArrayInputStream bis = new ByteArrayInputStream(Base64Util.decodeFromString(cert));
    ASN1InputStream dis = new ASN1InputStream(bis);
    ASN1Sequence seq = (ASN1Sequence)dis.readObject();
    return Certificate.getInstance(seq);
  }

  public static java.security.cert.Certificate buildJavaCert(String cert)
      throws CertificateException {
    ByteArrayInputStream bis = new ByteArrayInputStream(Base64Util.decodeFromString(cert));
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    return factory.generateCertificate(bis);
  }


  public static void main(String[] args) throws IOException, CertificateException {
    String cert = "-----BEGIN CERTIFICATE-----MIICETCCAbWgAwIBAgINKl81oFaaablKOp0YTjAMBggqgRzPVQGDdQUAMGExCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMSUwIwYDVQQLDBxCSkNBIEFueXdyaXRlIFRydXN0IFNlcnZpY2VzMRwwGgYDVQQDDBNUcnVzdC1TaWduIFNNMiBDQS0xMB4XDTIwMDgxMzIwMTkzNFoXDTIwMTAyNDE1NTk1OVowHjELMAkGA1UEBgwCQ04xDzANBgNVBAMMBuWGr+i9rDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAIF97Sqq0Rv616L2PjFP3xt16QGJLmi+W8Ht+NLHiXntgUey0Nz+ZVnSUKUMzkKuGTikY3h2v7la20b6lpKo8WjgZIwgY8wCwYDVR0PBAQDAgbAMB0GA1UdDgQWBBSxiaS6z4Uguz3MepS2zblkuAF/LTAfBgNVHSMEGDAWgBTMZyRCGsP4rSes0vLlhIEf6cUvrjBABgNVHSAEOTA3MDUGCSqBHIbvMgICAjAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczAMBggqgRzPVQGDdQUAA0gAMEUCIG6n6PG0BOK1EdFcvetQlC+9QhpsTuTui2wkeqWiPKYWAiEAvqR8Z+tSiYR5DIs7SyHJPWZ+sa8brtQL/1jURvHGxU8=-----END CERTIFICATE-----";
    CertificateFactory certificateFactory = new CertificateFactory();
    byte[] encoded = cert.getBytes(StandardCharsets.UTF_8);
    java.security.cert.Certificate certificate1 = certificateFactory.engineGenerateCertificate(new ASN1InputStream(encoded));
    System.out.println(Base64Util.encodeToString(certificate1.getEncoded()));
  }


}