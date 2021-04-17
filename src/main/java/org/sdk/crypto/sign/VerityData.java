package org.sdk.crypto.sign;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.sdk.crypto.cert.CertBuilder;
import org.sdk.crypto.key.KeyBuilder;
import org.sdk.crypto.utils.Base64Util;

public class VerityData {

  public static boolean verifySignedData(String alg, byte[] signData, byte[] sourceData, PublicKey key)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature signature = Signature.getInstance(alg);
    signature.initVerify(key);
    signature.update(sourceData);
    return signature.verify(signData);
  }


  public static void main(String[] args) throws Exception {
    String signData = "p/NTEtL2Yb+gBeQBDaP2MAchIIvThbw4sEw/kcQeK2LsVdSPBBVmllrNimM0Y3pDAPCL5lWd2dG1NXnl9cykMZEVMF73h3bR3PmhKUz7sYi/MQqpbbQ4nBk6J8fZ1qKLTWuCrdL7dkmvGWcN6D0qMMW2jFoU/ivho4ANGzD+qkY=";
    String cert= "MIIFKDCCBBCgAwIBAgIKLDAAAAAAAAMGhzANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJDTjENMAsGA1UECgwEQkpDQTEYMBYGA1UECwwPUHVibGljIFRydXN0IENBMRowGAYDVQQDDBFQdWJsaWMgVHJ1c3QgQ0EtMTAeFw0yMTAzMjkxNjAwMDBaFw0yMTA2MzAxNTU5NTlaMFAxCzAJBgNVBAYTAkNOMQ8wDQYDVQQKDAbogYLlkbMxMDAuBgNVBAMMJ+WMl+S6rOaVsOWtl+iupOivgea1i+ivlee7hOa1i+ivleS8geS4mjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA4YPLxDaZUIR54L7Wgl55GZXQgvodZ/CkEDzkUV6YwveujKIiwUEkiyKQ0wf/F42+Ez5Lam186sHFLQ8bc4y0FT4HdF9I2wp2LzK0NVTquWpRjqP33KNgCxZ625dULJG0HPwJ6P9XGw18UXbnry0S86Csw2W6yYFNnew1ffUOwC0CAwEAAaOCAoQwggKAMB8GA1UdIwQYMBaAFKw77K8Mo1AO76+vtE9sO9vRV9KJMB0GA1UdDgQWBBTHTaZV4S+cybIScnZKwJLMTgGOCTALBgNVHQ8EBAMCBsAwgbEGA1UdHwSBqTCBpjBsoGqgaKRmMGQxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDARCSkNBMRgwFgYDVQQLDA9QdWJsaWMgVHJ1c3QgQ0ExGjAYBgNVBAMMEVB1YmxpYyBUcnVzdCBDQS0xMRAwDgYDVQQDEwdjYTNjcmwyMDagNKAyhjBodHRwOi8vMTExLjIwNy4xNzcuMTg5OjgwMDMvY3JsL3B0Y2EvY2EzY3JsMi5jcmwwCQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMCAP8wGwYIKlaGSAGBMAEEDzk5ODAwMDEwMDM1NDA3ODAgBghghkgBhvhEAgQUU0YxMTUyNDIyMDAyMDkwNjc5NDUwHQYFKlYLBwkEFFNGMTE1MjQyMjAwMjA5MDY3OTQ1MCEGBipWCwcBCAQXMUNAU0YxMTUyNDIyMDAyMDkwNjc5NDUwQAYDVR0gBDkwNzA1BgkqgRyG7zICAgEwKDAmBggrBgEFBQcCARYaaHR0cDovL3d3dy5iamNhLm9yZy5jbi9jcHMwYgYIKwYBBQUHAQEEVjBUMCgGCCsGAQUFBzABhhxPQ1NQOi8vb2NzcC5iamNhLm9yZy5jbjo5MDEyMCgGCCsGAQUFBzAChhxodHRwOi8vY3JsLmJqY2Eub3JnL2NhaXNzdWVyMCAGCCqBHNAUBAEEBBQMEjExNTI0MjIwMDIwOTA2Nzk0NTAWBgoqgRyG7zICAQEeBAgMBjIwMjAwMzANBgkqhkiG9w0BAQsFAAOCAQEAI/khRI0ZPbUZJtkI8C9ds4OHpmO17t5DQysyeqjgqvP7b2me1S5hIV0ZdcD5VSQt/XoQ0pNZQ1BjFYiG7z90KDYcW/yOSDGoOn/GVCH+IoDyUeayspKA6/k3ttBNumrtgCoERGFHWDY1JLn73ppYR1AimiiFNAHWCpgimLDuN8j+pIIBfcKhKtNEFR1dCnD7Tra+5nWLAOH93lUGfuLxKQx0vbpPN8YZI+jDi77jJoLg25x7zzW5OTJbd2g1CrPaJlr1BqPF0HpYt+qthSAahD8e7IDL1MavvMWzQt42UnfMMDBGWNOnhCQcbDptoySTA7dTWPBLooN1Ln06pJbDpA==";
    String alg = "SHA1WithRSA";
    String source = "mvE1caNu9UFWNPWqarPXSRvWOGM=";

    Certificate certificate = CertBuilder.buildBcCert(cert);
    SubjectPublicKeyInfo subjectPublicKeyInfo = certificate.getSubjectPublicKeyInfo();
    PublicKey key = KeyBuilder.buildByteToKey("RSA", subjectPublicKeyInfo.getEncoded());
    boolean b = verifySignedData(alg, Base64Util.decodeFromString(signData),
        Base64Util.decodeFromString(source), key);
    System.out.println(b);
  }

}
