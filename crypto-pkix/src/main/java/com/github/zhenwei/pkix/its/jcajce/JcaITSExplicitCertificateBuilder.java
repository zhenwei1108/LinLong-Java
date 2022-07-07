package com.github.zhenwei.pkix.its.jcajce;

import com.github.zhenwei.pkix.its.ITSCertificate;
import com.github.zhenwei.pkix.its.ITSExplicitCertificateBuilder;
import com.github.zhenwei.pkix.its.ITSPublicEncryptionKey;
import com.github.zhenwei.pkix.its.operator.ITSContentSigner;
import com.github.zhenwei.pkix.util.oer.its.CertificateId;
import com.github.zhenwei.pkix.util.oer.its.ToBeSignedCertificate;
import com.github.zhenwei.provider.jcajce.util.DefaultJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.JcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.NamedJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.ProviderJcaJceHelper;
import java.security.Provider;
import java.security.interfaces.ECPublicKey;

public class JcaITSExplicitCertificateBuilder
    extends ITSExplicitCertificateBuilder {

  private JcaJceHelper helper;

  /**
   * Base constructor for an ITS certificate.
   *
   * @param signer         the content signer to be used to generate the signature validating the
   *                       certificate.
   * @param tbsCertificate
   */
  public JcaITSExplicitCertificateBuilder(ITSContentSigner signer,
      ToBeSignedCertificate.Builder tbsCertificate) {
    this(signer, tbsCertificate, new DefaultJcaJceHelper());
  }

  private JcaITSExplicitCertificateBuilder(ITSContentSigner signer,
      ToBeSignedCertificate.Builder tbsCertificate, JcaJceHelper helper) {
    super(signer, tbsCertificate);
    this.helper = helper;
  }

  public JcaITSExplicitCertificateBuilder setProvider(Provider provider) {
    this.helper = new ProviderJcaJceHelper(provider);
    return this;
  }

  public JcaITSExplicitCertificateBuilder setProvider(String providerName) {
    this.helper = new NamedJcaJceHelper(providerName);
    return this;
  }

  public ITSCertificate build(
      CertificateId certificateId,
      ECPublicKey verificationKey) {
    return build(certificateId, verificationKey, null);
  }

  public ITSCertificate build(
      CertificateId certificateId,
      ECPublicKey verificationKey,
      ECPublicKey encryptionKey) {
    ITSPublicEncryptionKey publicEncryptionKey = null;
    if (encryptionKey != null) {
      publicEncryptionKey = new JceITSPublicEncryptionKey(encryptionKey, helper);
    }

    return super.build(certificateId, new JcaITSPublicVerificationKey(verificationKey, helper),
        publicEncryptionKey);
  }
}