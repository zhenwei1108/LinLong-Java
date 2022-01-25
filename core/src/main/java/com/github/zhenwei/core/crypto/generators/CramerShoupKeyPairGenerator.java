package com.github.zhenwei.core.crypto.generators;

import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPair;
import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPairGenerator;
import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import com.github.zhenwei.core.crypto.params.CramerShoupKeyGenerationParameters;
import com.github.zhenwei.core.crypto.params.CramerShoupParameters;
import com.github.zhenwei.core.crypto.params.CramerShoupPrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.CramerShoupPublicKeyParameters;
import com.github.zhenwei.core.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * a Cramer Shoup key pair generator
 */
public class CramerShoupKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator {

  private static final BigInteger ONE = BigInteger.valueOf(1);

  private CramerShoupKeyGenerationParameters param;

  public void init(KeyGenerationParameters param) {
    this.param = (CramerShoupKeyGenerationParameters) param;
  }

  public AsymmetricCipherKeyPair generateKeyPair() {
    CramerShoupParameters csParams = param.getParameters();

    CramerShoupPrivateKeyParameters sk = generatePrivateKey(param.getRandom(), csParams);
    CramerShoupPublicKeyParameters pk = calculatePublicKey(csParams, sk);
    sk.setPk(pk);

    return new AsymmetricCipherKeyPair(pk, sk);
  }

  private BigInteger generateRandomElement(BigInteger p, SecureRandom random) {
    return BigIntegers.createRandomInRange(ONE, p.subtract(ONE), random);
  }

  private CramerShoupPrivateKeyParameters generatePrivateKey(SecureRandom random,
      CramerShoupParameters csParams) {
    BigInteger p = csParams.getP();
    CramerShoupPrivateKeyParameters key = new CramerShoupPrivateKeyParameters(csParams,
        generateRandomElement(p, random), generateRandomElement(p, random),
        generateRandomElement(p, random), generateRandomElement(p, random),
        generateRandomElement(p, random));
    return key;
  }

  private CramerShoupPublicKeyParameters calculatePublicKey(CramerShoupParameters csParams,
      CramerShoupPrivateKeyParameters sk) {
    BigInteger g1 = csParams.getG1();
    BigInteger g2 = csParams.getG2();
    BigInteger p = csParams.getP();

    BigInteger c = g1.modPow(sk.getX1(), p).multiply(g2.modPow(sk.getX2(), p));
    BigInteger d = g1.modPow(sk.getY1(), p).multiply(g2.modPow(sk.getY2(), p));
    BigInteger h = g1.modPow(sk.getZ(), p);

    return new CramerShoupPublicKeyParameters(csParams, c, d, h);
  }
}