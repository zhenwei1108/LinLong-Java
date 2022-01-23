package com.github.zhenwei.core.crypto.generators;

import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPair;
import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPairGenerator;
import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import com.github.zhenwei.core.crypto.params.DHKeyGenerationParameters;
import com.github.zhenwei.core.crypto.params.DHParameters;
import com.github.zhenwei.core.crypto.params.DHPrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.DHPublicKeyParameters;
import java.math.BigInteger;


/**
 * a Diffie-Hellman key pair generator.
 * <p>
 * This generates keys consistent for use in the MTI/A0 key agreement protocol as described in
 * "Handbook of Applied Cryptography", Pages 516-519.
 */
public class DHKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator {

  private DHKeyGenerationParameters param;

  public void init(
      KeyGenerationParameters param) {
    this.param = (DHKeyGenerationParameters) param;
  }

  public AsymmetricCipherKeyPair generateKeyPair() {
    DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
    DHParameters dhp = param.getParameters();

    BigInteger x = helper.calculatePrivate(dhp, param.getRandom());
    BigInteger y = helper.calculatePublic(dhp, x);

    return new AsymmetricCipherKeyPair(
        new DHPublicKeyParameters(y, dhp),
        new DHPrivateKeyParameters(x, dhp));
  }
}