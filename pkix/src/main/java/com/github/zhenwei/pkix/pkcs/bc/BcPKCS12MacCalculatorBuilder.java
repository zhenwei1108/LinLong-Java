package com.github.zhenwei.pkix.pkcs.bc;

import com.github.zhenwei.core.asn1.DERNull;
import com.github.zhenwei.core.asn1.oiw.OIWObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCS12PBEParams;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.ExtendedDigest;
import com.github.zhenwei.core.crypto.digests.SHA1Digest;
import com.github.zhenwei.pkix.operator.MacCalculator;
import com.github.zhenwei.pkix.pkcs.PKCS12MacCalculatorBuilder;
import java.security.SecureRandom;

public class BcPKCS12MacCalculatorBuilder
    implements PKCS12MacCalculatorBuilder {

  private ExtendedDigest digest;
  private AlgorithmIdentifier algorithmIdentifier;

  private SecureRandom random;
  private int saltLength;
  private int iterationCount = 1024;

  public BcPKCS12MacCalculatorBuilder() {
    this(new SHA1Digest(), new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE));
  }

  public BcPKCS12MacCalculatorBuilder(ExtendedDigest digest,
      AlgorithmIdentifier algorithmIdentifier) {
    this.digest = digest;
    this.algorithmIdentifier = algorithmIdentifier;
    this.saltLength = digest.getDigestSize();
  }

  public BcPKCS12MacCalculatorBuilder setIterationCount(int iterationCount) {
    this.iterationCount = iterationCount;

    return this;
  }

  public AlgorithmIdentifier getDigestAlgorithmIdentifier() {
    return algorithmIdentifier;
  }

  public MacCalculator build(final char[] password) {
    if (random == null) {
      random = new SecureRandom();
    }

    byte[] salt = new byte[saltLength];

    random.nextBytes(salt);

    return PKCS12PBEUtils.createMacCalculator(algorithmIdentifier.getAlgorithm(), digest,
        new PKCS12PBEParams(salt, iterationCount), password);
  }
}