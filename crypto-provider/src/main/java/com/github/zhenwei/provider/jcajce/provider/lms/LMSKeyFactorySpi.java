package com.github.zhenwei.provider.jcajce.provider.lms;

import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.provider.jcajce.provider.util.AsymmetricKeyInfoConverter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class LMSKeyFactorySpi
    extends KeyFactorySpi
    implements AsymmetricKeyInfoConverter {

  public PrivateKey engineGeneratePrivate(KeySpec keySpec)
      throws InvalidKeySpecException {
    if (keySpec instanceof PKCS8EncodedKeySpec) {
      // get the DER-encoded Key according to PKCS#8 from the spec
      byte[] encKey = ((PKCS8EncodedKeySpec) keySpec).getEncoded();

      try {
        return generatePrivate(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(encKey)));
      } catch (Exception e) {
        throw new InvalidKeySpecException(e.toString(), e);
      }
    }

    throw new InvalidKeySpecException("unsupported key specification: "
        + keySpec.getClass() + ".");
  }

  public PublicKey engineGeneratePublic(KeySpec keySpec)
      throws InvalidKeySpecException {
    if (keySpec instanceof X509EncodedKeySpec) {
      // get the DER-encoded Key according to X.509 from the spec
      byte[] encKey = ((X509EncodedKeySpec) keySpec).getEncoded();

      // decode the SubjectPublicKeyInfo data structure to the pki object
      try {
        return generatePublic(SubjectPublicKeyInfo.getInstance(encKey));
      } catch (Exception e) {
        throw new InvalidKeySpecException(e.toString(), e);
      }
    }

    throw new InvalidKeySpecException("unknown key specification: " + keySpec + ".");
  }

  public final KeySpec engineGetKeySpec(Key key, Class keySpec)
      throws InvalidKeySpecException {
    if (key instanceof BCLMSPrivateKey) {
      if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
        return new PKCS8EncodedKeySpec(key.getEncoded());
      }
    } else if (key instanceof BCLMSPublicKey) {
      if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
        return new X509EncodedKeySpec(key.getEncoded());
      }
    } else {
      throw new InvalidKeySpecException("unsupported key type: "
          + key.getClass() + ".");
    }

    throw new InvalidKeySpecException("unknown key specification: "
        + keySpec + ".");
  }

  public final Key engineTranslateKey(Key key)
      throws InvalidKeyException {
    if (key instanceof BCLMSPrivateKey || key instanceof BCLMSPublicKey) {
      return key;
    }

    throw new InvalidKeyException("unsupported key type");
  }

  public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
      throws IOException {
    return new BCLMSPrivateKey(keyInfo);
  }

  public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
      throws IOException {
    return new BCLMSPublicKey(keyInfo);
  }
}