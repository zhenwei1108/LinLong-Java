package com.github.zhenwei.pkix.its;

import com.github.zhenwei.core.util.Encodable;
import com.github.zhenwei.pkix.its.operator.ECDSAEncoder;
import com.github.zhenwei.pkix.its.operator.ITSContentVerifierProvider;
import com.github.zhenwei.pkix.operator.ContentVerifier;
import com.github.zhenwei.pkix.util.oer.OEREncoder;
import com.github.zhenwei.pkix.util.oer.its.Certificate;
import com.github.zhenwei.pkix.util.oer.its.IssuerIdentifier;
import com.github.zhenwei.pkix.util.oer.its.PublicEncryptionKey;
import com.github.zhenwei.pkix.util.oer.its.Signature;
import com.github.zhenwei.pkix.util.oer.its.template.IEEE1609dot2;
import java.io.IOException;
import java.io.OutputStream;

public class ITSCertificate
    implements Encodable {

  private final Certificate certificate;

  public ITSCertificate(Certificate certificate) {
    this.certificate = certificate;
  }

  public IssuerIdentifier getIssuer() {
    return certificate.getCertificateBase().getIssuer();
  }

  public ITSValidityPeriod getValidityPeriod() {
    return new ITSValidityPeriod(
        certificate.getCertificateBase().getToBeSignedCertificate().getValidityPeriod());
  }

  /**
   * Return the certificate's public encryption key, if present.
   *
   * @return
   */
  public ITSPublicEncryptionKey getPublicEncryptionKey() {
    PublicEncryptionKey encryptionKey = certificate.getCertificateBase().getToBeSignedCertificate()
        .getEncryptionKey();

    if (encryptionKey != null) {
      return new ITSPublicEncryptionKey(encryptionKey);
    }

    return null;
  }

  public boolean isSignatureValid(ITSContentVerifierProvider verifierProvider)
      throws Exception {
    ContentVerifier contentVerifier = verifierProvider.get(
        certificate.getCertificateBase().getSignature().getChoice());

    OutputStream verOut = contentVerifier.getOutputStream();

    verOut.write(
        OEREncoder.toByteArray(certificate.getCertificateBase().getToBeSignedCertificate(),
            IEEE1609dot2.tbsCertificate));

    verOut.close();

    Signature sig = certificate.getCertificateBase().getSignature();

    return contentVerifier.verify(ECDSAEncoder.toX962(sig));
  }

  public Certificate toASN1Structure() {
    return certificate;
  }

  public byte[] getEncoded()
      throws IOException {
    return OEREncoder.toByteArray(certificate.getCertificateBase(), IEEE1609dot2.certificate);
  }
}