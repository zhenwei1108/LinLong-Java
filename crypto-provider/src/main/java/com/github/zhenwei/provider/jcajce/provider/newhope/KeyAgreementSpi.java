package com.github.zhenwei.provider.jcajce.provider.newhope;

import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.pqc.crypto.ExchangePair;
import com.github.zhenwei.core.pqc.crypto.newhope.NHAgreement;
import com.github.zhenwei.core.pqc.crypto.newhope.NHExchangePairGenerator;
import com.github.zhenwei.core.pqc.crypto.newhope.NHPublicKeyParameters;
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.ShortBufferException;

public class KeyAgreementSpi
    extends BaseAgreementSpi {

  private NHAgreement agreement;
  private BCNHPublicKey otherPartyKey;
  private NHExchangePairGenerator exchangePairGenerator;

  private byte[] shared;

  public KeyAgreementSpi() {
    super("NH", null);
  }

  protected void engineInit(Key key, SecureRandom secureRandom)
      throws InvalidKeyException {
    if (key != null) {
      agreement = new NHAgreement();

      agreement.init(((BCNHPrivateKey) key).getKeyParams());
    } else {
      exchangePairGenerator = new NHExchangePairGenerator(secureRandom);
    }
  }

  protected void engineInit(Key key, AlgorithmParameterSpec algorithmParameterSpec,
      SecureRandom secureRandom)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    throw new InvalidAlgorithmParameterException("NewHope does not require parameters");
  }

  protected Key engineDoPhase(Key key, boolean lastPhase)
      throws InvalidKeyException, IllegalStateException {
    if (!lastPhase) {
      throw new IllegalStateException("NewHope can only be between two parties.");
    }

    otherPartyKey = (BCNHPublicKey) key;

    if (exchangePairGenerator != null) {
      ExchangePair exchPair = exchangePairGenerator.generateExchange(
          (AsymmetricKeyParameter) otherPartyKey.getKeyParams());

      shared = exchPair.getSharedValue();

      return new BCNHPublicKey((NHPublicKeyParameters) exchPair.getPublicKey());
    } else {
      shared = agreement.calculateAgreement(otherPartyKey.getKeyParams());

      return null;
    }
  }

  protected byte[] engineGenerateSecret()
      throws IllegalStateException {
    byte[] rv = Arrays.clone(shared);

    Arrays.fill(shared, (byte) 0);

    return rv;
  }

  protected int engineGenerateSecret(byte[] bytes, int offset)
      throws IllegalStateException, ShortBufferException {
    System.arraycopy(shared, 0, bytes, offset, shared.length);

    Arrays.fill(shared, (byte) 0);

    return shared.length;
  }

  protected byte[] calcSecret() {
    return engineGenerateSecret();
  }
}