package com.github.zhenwei.pkix.its.bc;

import com.github.zhenwei.core.crypto.params.ECPublicKeyParameters;
import com.github.zhenwei.pkix.its.ITSCertificate;
import com.github.zhenwei.pkix.its.ITSExplicitCertificateBuilder;
import com.github.zhenwei.pkix.its.ITSPublicEncryptionKey;
import com.github.zhenwei.pkix.its.operator.ITSContentSigner;
import com.github.zhenwei.pkix.util.oer.its.CertificateId;
import com.github.zhenwei.pkix.util.oer.its.ToBeSignedCertificate;

public class BcITSExplicitCertificateBuilder
    extends ITSExplicitCertificateBuilder {

  /**
   * Base constructor for an ITS certificate.
   *
   * @param signer         the content signer to be used to generate the signature validating the
   *                       certificate.
   * @param tbsCertificate
   */
  public BcITSExplicitCertificateBuilder(ITSContentSigner signer,
      ToBeSignedCertificate.Builder tbsCertificate) {
    super(signer, tbsCertificate);
  }

  public ITSCertificate build(
      CertificateId certificateId,
      ECPublicKeyParameters verificationKey) {

    return build(certificateId, verificationKey, null);
  }

  public ITSCertificate build(
      CertificateId certificateId,
      ECPublicKeyParameters verificationKey,
      ECPublicKeyParameters encryptionKey) {
    ITSPublicEncryptionKey publicEncryptionKey = null;
    if (encryptionKey != null) {
      publicEncryptionKey = new BcITSPublicEncryptionKey(encryptionKey);
    }

    return super.build(certificateId, new BcITSPublicVerificationKey(verificationKey),
        publicEncryptionKey);
  }
}