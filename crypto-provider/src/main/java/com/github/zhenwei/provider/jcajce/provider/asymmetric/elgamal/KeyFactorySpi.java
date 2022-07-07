package com.github.zhenwei.provider.jcajce.provider.asymmetric.elgamal;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.oiw.OIWObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.asn1.x9.X9ObjectIdentifiers;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import com.github.zhenwei.provider.jce.interfaces.ElGamalPrivateKey;
import com.github.zhenwei.provider.jce.interfaces.ElGamalPublicKey;
import com.github.zhenwei.provider.jce.spec.ElGamalPrivateKeySpec;
import com.github.zhenwei.provider.jce.spec.ElGamalPublicKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

public class KeyFactorySpi
    extends BaseKeyFactorySpi {

  public KeyFactorySpi() {
  }

  protected PrivateKey engineGeneratePrivate(
      KeySpec keySpec)
      throws InvalidKeySpecException {
    if (keySpec instanceof ElGamalPrivateKeySpec) {
      return new BCElGamalPrivateKey((ElGamalPrivateKeySpec) keySpec);
    } else if (keySpec instanceof DHPrivateKeySpec) {
      return new BCElGamalPrivateKey((DHPrivateKeySpec) keySpec);
    }

    return super.engineGeneratePrivate(keySpec);
  }

  protected PublicKey engineGeneratePublic(
      KeySpec keySpec)
      throws InvalidKeySpecException {
    if (keySpec instanceof ElGamalPublicKeySpec) {
      return new BCElGamalPublicKey((ElGamalPublicKeySpec) keySpec);
    } else if (keySpec instanceof DHPublicKeySpec) {
      return new BCElGamalPublicKey((DHPublicKeySpec) keySpec);
    }
    return super.engineGeneratePublic(keySpec);
  }

  protected KeySpec engineGetKeySpec(
      Key key,
      Class spec)
      throws InvalidKeySpecException {
    if (spec.isAssignableFrom(DHPrivateKeySpec.class) && key instanceof DHPrivateKey) {
      DHPrivateKey k = (DHPrivateKey) key;

      return new DHPrivateKeySpec(k.getX(), k.getParams().getP(), k.getParams().getG());
    } else if (spec.isAssignableFrom(DHPublicKeySpec.class) && key instanceof DHPublicKey) {
      DHPublicKey k = (DHPublicKey) key;

      return new DHPublicKeySpec(k.getY(), k.getParams().getP(), k.getParams().getG());
    }

    return super.engineGetKeySpec(key, spec);
  }

  protected Key engineTranslateKey(
      Key key)
      throws InvalidKeyException {
    if (key instanceof DHPublicKey) {
      return new BCElGamalPublicKey((DHPublicKey) key);
    } else if (key instanceof DHPrivateKey) {
      return new BCElGamalPrivateKey((DHPrivateKey) key);
    } else if (key instanceof ElGamalPublicKey) {
      return new BCElGamalPublicKey((ElGamalPublicKey) key);
    } else if (key instanceof ElGamalPrivateKey) {
      return new BCElGamalPrivateKey((ElGamalPrivateKey) key);
    }

    throw new InvalidKeyException("key type unknown");
  }

  public PrivateKey generatePrivate(PrivateKeyInfo info)
      throws IOException {
    ASN1ObjectIdentifier algOid = info.getPrivateKeyAlgorithm().getAlgorithm();

    if (algOid.equals(PKCSObjectIdentifiers.dhKeyAgreement)) {
      return new BCElGamalPrivateKey(info);
    } else if (algOid.equals(X9ObjectIdentifiers.dhpublicnumber)) {
      return new BCElGamalPrivateKey(info);
    } else if (algOid.equals(OIWObjectIdentifiers.elGamalAlgorithm)) {
      return new BCElGamalPrivateKey(info);
    } else {
      throw new IOException("algorithm identifier " + algOid + " in key not recognised");
    }
  }

  public PublicKey generatePublic(SubjectPublicKeyInfo info)
      throws IOException {
    ASN1ObjectIdentifier algOid = info.getAlgorithm().getAlgorithm();

    if (algOid.equals(PKCSObjectIdentifiers.dhKeyAgreement)) {
      return new BCElGamalPublicKey(info);
    } else if (algOid.equals(X9ObjectIdentifiers.dhpublicnumber)) {
      return new BCElGamalPublicKey(info);
    } else if (algOid.equals(OIWObjectIdentifiers.elGamalAlgorithm)) {
      return new BCElGamalPublicKey(info);
    } else {
      throw new IOException("algorithm identifier " + algOid + " in key not recognised");
    }
  }
}