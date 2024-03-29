package com.github.zhenwei.pkix.its.jcajce;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.nist.NISTNamedCurves;
import com.github.zhenwei.core.asn1.sec.SECObjectIdentifiers;
import com.github.zhenwei.core.asn1.teletrust.TeleTrusTNamedCurves;
import com.github.zhenwei.core.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.asn1.x9.X9ECParameters;
import com.github.zhenwei.core.math.ec.ECCurve;
import com.github.zhenwei.core.math.ec.ECPoint;
import com.github.zhenwei.pkix.its.ITSPublicEncryptionKey;
import com.github.zhenwei.pkix.util.oer.its.BasePublicEncryptionKey;
import com.github.zhenwei.pkix.util.oer.its.EccCurvePoint;
import com.github.zhenwei.pkix.util.oer.its.EccP256CurvePoint;
import com.github.zhenwei.pkix.util.oer.its.EccP384CurvePoint;
import com.github.zhenwei.pkix.util.oer.its.PublicEncryptionKey;
import com.github.zhenwei.pkix.util.oer.its.SymmAlgorithm;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.util.EC5Util;
import com.github.zhenwei.provider.jcajce.util.DefaultJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.JcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.NamedJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.ProviderJcaJceHelper;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;

public class JceITSPublicEncryptionKey
    extends ITSPublicEncryptionKey {

  private final JcaJceHelper helper;

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

    public JceITSPublicEncryptionKey build(PublicEncryptionKey encryptionKey) {
      return new JceITSPublicEncryptionKey(encryptionKey, helper);
    }

    public JceITSPublicEncryptionKey build(PublicKey encryptionKey) {
      return new JceITSPublicEncryptionKey(encryptionKey, helper);
    }
  }

  JceITSPublicEncryptionKey(PublicEncryptionKey encryptionKey, JcaJceHelper helper) {
    super(encryptionKey);
    this.helper = helper;
  }

  JceITSPublicEncryptionKey(PublicKey encryptionKey, JcaJceHelper helper) {
    super(fromPublicKey(encryptionKey));
    this.helper = helper;
  }

  static PublicEncryptionKey fromPublicKey(PublicKey key) {
    if (!(key instanceof ECPublicKey)) {
      throw new IllegalArgumentException("must be ECPublicKey instance");
    }

    ECPublicKey pKey = (ECPublicKey) key;

    ASN1ObjectIdentifier curveID = ASN1ObjectIdentifier.getInstance(
        SubjectPublicKeyInfo.getInstance(key.getEncoded()).getAlgorithm().getParameters());

    if (curveID.equals(SECObjectIdentifiers.secp256r1)) {
      return new PublicEncryptionKey(
          SymmAlgorithm.aes128Ccm,
          new BasePublicEncryptionKey.Builder()
              .setChoice(BasePublicEncryptionKey.eciesNistP256)
              .setValue(EccP256CurvePoint.builder()
                  .createUncompressedP256(
                      pKey.getW().getAffineX(),
                      pKey.getW().getAffineY()))
              .createBasePublicEncryptionKey());
    } else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1)) {
      return new PublicEncryptionKey(
          SymmAlgorithm.aes128Ccm,
          new BasePublicEncryptionKey.Builder()
              .setChoice(BasePublicEncryptionKey.eciesBrainpoolP256r1)
              .setValue(EccP256CurvePoint.builder()
                  .createUncompressedP256(
                      pKey.getW().getAffineX(),
                      pKey.getW().getAffineY()))
              .createBasePublicEncryptionKey());
    } else {
      throw new IllegalArgumentException("unknown curve in public encryption key");
    }

  }

  public PublicKey getKey() {
    BasePublicEncryptionKey baseKey = encryptionKey.getBasePublicEncryptionKey();
    X9ECParameters params;

    switch (baseKey.getChoice()) {
      case BasePublicEncryptionKey.eciesNistP256:

        params = NISTNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
        break;
      case BasePublicEncryptionKey.eciesBrainpoolP256r1:
        params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256r1);
        break;
      default:
        throw new IllegalStateException("unknown key type");
    }

    ASN1Encodable pviCurvePoint = encryptionKey.getBasePublicEncryptionKey().getValue();
    final EccCurvePoint itsPoint;
    if (pviCurvePoint instanceof EccCurvePoint) {
      itsPoint = (EccCurvePoint) baseKey.getValue();
    } else {
      throw new IllegalStateException("extension to public verification key not supported");
    }
    ECCurve curve = params.getCurve();

    byte[] key;
    if (itsPoint instanceof EccP256CurvePoint) {
      key = itsPoint.getEncodedPoint();
    } else if (itsPoint instanceof EccP384CurvePoint) {
      key = itsPoint.getEncodedPoint();
    } else {
      throw new IllegalStateException("unknown key type");
    }

    ECPoint point = curve.decodePoint(key).normalize();

    try {
      KeyFactory keyFactory = helper.createKeyFactory("EC");
      ECParameterSpec spec = EC5Util.convertToSpec(params);
      java.security.spec.ECPoint jPoint = EC5Util.convertPoint(point);
      return keyFactory.generatePublic(new ECPublicKeySpec(jPoint, spec));
    } catch (Exception e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }
}