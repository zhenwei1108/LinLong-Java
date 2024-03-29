package com.github.zhenwei.pkix.its.jcajce;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.nist.NISTObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.asn1.sec.SECObjectIdentifiers;
import com.github.zhenwei.core.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.pkix.its.ITSCertificate;
import com.github.zhenwei.pkix.its.operator.ITSContentSigner;
import com.github.zhenwei.pkix.operator.DigestCalculator;
import com.github.zhenwei.pkix.operator.DigestCalculatorProvider;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import com.github.zhenwei.pkix.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import com.github.zhenwei.provider.jcajce.util.DefaultJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.JcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.NamedJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.ProviderJcaJceHelper;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;

public class JcaITSContentSigner
    implements ITSContentSigner {

  public static class Builder {

    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public Builder setProvider(Provider provider) {
      this.helper = new ProviderJcaJceHelper(provider);

      return this;
    }

    public Builder setProvider(String providerName) {
      this.helper = new NamedJcaJceHelper(providerName);

      return this;
    }

    public JcaITSContentSigner build(PrivateKey privateKey) {
      return new JcaITSContentSigner((ECPrivateKey) privateKey, null, helper);
    }

    public JcaITSContentSigner build(PrivateKey privateKey, ITSCertificate signerCert) {
      return new JcaITSContentSigner((ECPrivateKey) privateKey, signerCert, helper);
    }
  }

  private final ECPrivateKey privateKey;
  private final ITSCertificate signerCert;
  private final AlgorithmIdentifier digestAlgo;
  private final DigestCalculator digest;
  private final byte[] parentData;
  private final ASN1ObjectIdentifier curveID;
  private final byte[] parentDigest;
  private final String signer;
  private final JcaJceHelper helper;

  private JcaITSContentSigner(ECPrivateKey privateKey, ITSCertificate signerCert,
      JcaJceHelper helper) {
    this.privateKey = privateKey;
    this.signerCert = signerCert;
    this.helper = helper;

    //
    // Probably the most generic way at the moment.
    //

    PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
    curveID = ASN1ObjectIdentifier.getInstance(pkInfo.getPrivateKeyAlgorithm().getParameters());

    if (curveID.equals(SECObjectIdentifiers.secp256r1)) {
      digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
      signer = "SHA256withECDSA";
    } else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1)) {
      digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
      signer = "SHA256withECDSA";
    } else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1)) {
      digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
      signer = "SHA384withECDSA";
    } else {
      throw new IllegalArgumentException("unknown key type");
    }

    DigestCalculatorProvider digestCalculatorProvider;

    try {

      JcaDigestCalculatorProviderBuilder bld = new JcaDigestCalculatorProviderBuilder().setHelper(
          helper);
      digestCalculatorProvider = bld.build();
    } catch (Exception ex) {
      throw new IllegalStateException(ex.getMessage(), ex);
    }

    try {
      digest = digestCalculatorProvider.get(digestAlgo);
    } catch (OperatorCreationException e) {
      throw new IllegalStateException("cannot recognise digest type: " + digestAlgo.getAlgorithm(),
          e);
    }

    if (signerCert != null) {
      try {
        parentData = signerCert.getEncoded();
        digest.getOutputStream().write(parentData, 0, parentData.length);
        parentDigest = digest.getDigest();
      } catch (IOException e) {
        throw new IllegalStateException("signer certificate encoding failed: " + e.getMessage());
      }
    } else {
      // self signed so we use a null digest for the parent.
      this.parentData = null;
      this.parentDigest = digest.getDigest();
    }

  }

  @Override
  public OutputStream getOutputStream() {
    return digest.getOutputStream();
  }

  @Override
  public byte[] getSignature() {
    byte[] clientCertDigest = digest.getDigest();
    Signature signature;
    try {
      signature = helper.createSignature(signer);
      signature.initSign(privateKey);
      signature.update(clientCertDigest, 0, clientCertDigest.length);
      signature.update(digest.getDigest());
      return signature.sign();
    } catch (Exception e) {
      throw new RuntimeException(e.getMessage(), e);
    }
  }

  @Override
  public ITSCertificate getAssociatedCertificate() {
    return signerCert;
  }

  @Override
  public byte[] getAssociatedCertificateDigest() {
    return Arrays.clone(parentDigest);
  }

  @Override
  public AlgorithmIdentifier getDigestAlgorithm() {
    return digestAlgo;
  }

  @Override
  public boolean isForSelfSigning() {
    return parentData == null;
  }
}