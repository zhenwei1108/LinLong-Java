package com.github.zhenwei.pkix.pkcs.bc;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.pkcs.PKCS12PBEParams;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.BlockCipher;
import com.github.zhenwei.core.crypto.BufferedBlockCipher;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.ExtendedDigest;
import com.github.zhenwei.core.crypto.digests.SHA1Digest;
import com.github.zhenwei.core.crypto.generators.PKCS12ParametersGenerator;
import com.github.zhenwei.core.crypto.io.CipherOutputStream;
import com.github.zhenwei.core.crypto.paddings.PKCS7Padding;
import com.github.zhenwei.core.crypto.paddings.PaddedBufferedBlockCipher;
import com.github.zhenwei.pkix.operator.GenericKey;
import com.github.zhenwei.pkix.operator.OutputEncryptor;
import java.io.OutputStream;
import java.security.SecureRandom;

public class BcPKCS12PBEOutputEncryptorBuilder {

  private ExtendedDigest digest;

  private BufferedBlockCipher engine;
  private ASN1ObjectIdentifier algorithm;
  private SecureRandom random;
  private int iterationCount = 1024;

  public BcPKCS12PBEOutputEncryptorBuilder(ASN1ObjectIdentifier algorithm, BlockCipher engine) {
    this(algorithm, engine, new SHA1Digest());
  }

  public BcPKCS12PBEOutputEncryptorBuilder(ASN1ObjectIdentifier algorithm, BlockCipher engine,
      ExtendedDigest pbeDigest) {
    this.algorithm = algorithm;
    this.engine = new PaddedBufferedBlockCipher(engine, new PKCS7Padding());
    this.digest = pbeDigest;
  }

  public BcPKCS12PBEOutputEncryptorBuilder setIterationCount(int iterationCount) {
    this.iterationCount = iterationCount;
    return this;
  }

  public OutputEncryptor build(final char[] password) {
    if (random == null) {
      random = new SecureRandom();
    }

    final byte[] salt = new byte[20];

    random.nextBytes(salt);

    final PKCS12PBEParams pbeParams = new PKCS12PBEParams(salt, iterationCount);

    CipherParameters params = PKCS12PBEUtils.createCipherParameters(algorithm, digest,
        engine.getBlockSize(), pbeParams, password);

    engine.init(true, params);

    return new OutputEncryptor() {
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return new AlgorithmIdentifier(algorithm, pbeParams);
      }

      public OutputStream getOutputStream(OutputStream out) {
        return new CipherOutputStream(out, engine);
      }

      public GenericKey getKey() {
        return new GenericKey(new AlgorithmIdentifier(algorithm, pbeParams),
            PKCS12ParametersGenerator.PKCS12PasswordToBytes(password));
      }
    };
  }
}