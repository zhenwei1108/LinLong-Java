package com.github.zhenwei.provider.jcajce.provider.sphincs;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.nist.NISTObjectIdentifiers;
import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPair;
import com.github.zhenwei.core.crypto.CryptoServicesRegistrar;
import com.github.zhenwei.core.crypto.digests.SHA3Digest;
import com.github.zhenwei.core.crypto.digests.SHA512tDigest;
import com.github.zhenwei.core.pqc.crypto.sphincs.SPHINCS256KeyGenerationParameters;
import com.github.zhenwei.core.pqc.crypto.sphincs.SPHINCS256KeyPairGenerator;
import com.github.zhenwei.core.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import com.github.zhenwei.core.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import com.github.zhenwei.provider.jcajce.spec.SPHINCS256KeyGenParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class Sphincs256KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator {

  ASN1ObjectIdentifier treeDigest = NISTObjectIdentifiers.id_sha512_256;

  SPHINCS256KeyGenerationParameters param;
  SPHINCS256KeyPairGenerator engine = new SPHINCS256KeyPairGenerator();

  SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
  boolean initialised = false;

  public Sphincs256KeyPairGeneratorSpi() {
    super("SPHINCS256");
  }

  public void initialize(
      int strength,
      SecureRandom random) {
    throw new IllegalArgumentException("use AlgorithmParameterSpec");
  }

  public void initialize(
      AlgorithmParameterSpec params,
      SecureRandom random)
      throws InvalidAlgorithmParameterException {
    if (!(params instanceof SPHINCS256KeyGenParameterSpec)) {
      throw new InvalidAlgorithmParameterException(
          "parameter object not a SPHINCS256KeyGenParameterSpec");
    }

    SPHINCS256KeyGenParameterSpec sphincsParams = (SPHINCS256KeyGenParameterSpec) params;

    if (sphincsParams.getTreeDigest().equals(SPHINCS256KeyGenParameterSpec.SHA512_256)) {
      treeDigest = NISTObjectIdentifiers.id_sha512_256;
      param = new SPHINCS256KeyGenerationParameters(random, new SHA512tDigest(256));
    } else if (sphincsParams.getTreeDigest().equals(SPHINCS256KeyGenParameterSpec.SHA3_256)) {
      treeDigest = NISTObjectIdentifiers.id_sha3_256;
      param = new SPHINCS256KeyGenerationParameters(random, new SHA3Digest(256));
    }

    engine.init(param);
    initialised = true;
  }

  public KeyPair generateKeyPair() {
    if (!initialised) {
      param = new SPHINCS256KeyGenerationParameters(random, new SHA512tDigest(256));

      engine.init(param);
      initialised = true;
    }

    AsymmetricCipherKeyPair pair = engine.generateKeyPair();
    SPHINCSPublicKeyParameters pub = (SPHINCSPublicKeyParameters) pair.getPublic();
    SPHINCSPrivateKeyParameters priv = (SPHINCSPrivateKeyParameters) pair.getPrivate();

    return new KeyPair(new BCSphincs256PublicKey(treeDigest, pub),
        new BCSphincs256PrivateKey(treeDigest, priv));
  }
}