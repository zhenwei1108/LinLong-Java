package com.github.zhenwei.pkix.cert.selector.jcajce;

import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.x500.X500Name;
import com.github.zhenwei.core.asn1.x509.Extension;
import com.github.zhenwei.pkix.cert.selector.X509CertificateHolderSelector;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

public class JcaX509CertificateHolderSelector
    extends X509CertificateHolderSelector {

  /**
   * Construct a signer identifier based on the issuer, serial number and subject key identifier (if
   * present) of the passed in certificate.
   *
   * @param certificate certificate providing the issue and serial number and subject key
   *                    identifier.
   */
  public JcaX509CertificateHolderSelector(X509Certificate certificate) {
    super(convertPrincipal(certificate.getIssuerX500Principal()), certificate.getSerialNumber(),
        getSubjectKeyId(certificate));
  }

  /**
   * Construct a signer identifier based on the provided issuer and serial number..
   *
   * @param issuer       the issuer to use.
   * @param serialNumber the serial number to use.
   */
  public JcaX509CertificateHolderSelector(X500Principal issuer, BigInteger serialNumber) {
    super(convertPrincipal(issuer), serialNumber);
  }

  /**
   * Construct a signer identifier based on the provided issuer, serial number, and subjectKeyId..
   *
   * @param issuer       the issuer to use.
   * @param serialNumber the serial number to use.
   * @param subjectKeyId the subject key ID to use.
   */
  public JcaX509CertificateHolderSelector(X500Principal issuer, BigInteger serialNumber,
      byte[] subjectKeyId) {
    super(convertPrincipal(issuer), serialNumber, subjectKeyId);
  }

  private static X500Name convertPrincipal(X500Principal issuer) {
    if (issuer == null) {
      return null;
    }
    return X500Name.getInstance(issuer.getEncoded());
  }

  private static byte[] getSubjectKeyId(X509Certificate cert) {
    byte[] ext = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());

    if (ext != null) {
      return ASN1OctetString.getInstance(ASN1OctetString.getInstance(ext).getOctets()).getOctets();
    } else {
      return null;
    }
  }
}