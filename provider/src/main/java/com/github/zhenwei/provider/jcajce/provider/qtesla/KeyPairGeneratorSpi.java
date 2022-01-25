package com.github.zhenwei.provider.jcajce.provider.qtesla;

import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPair;
import com.github.zhenwei.core.crypto.CryptoServicesRegistrar;
import com.github.zhenwei.core.pqc.crypto.qtesla.QTESLAKeyGenerationParameters;
import com.github.zhenwei.core.pqc.crypto.qtesla.QTESLAKeyPairGenerator;
import com.github.zhenwei.core.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import com.github.zhenwei.core.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import com.github.zhenwei.core.pqc.crypto.qtesla.QTESLASecurityCategory;
import com.github.zhenwei.core.util.Integers;
import com.github.zhenwei.provider.jcajce.spec.QTESLAParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator {

  private static final Map catLookup = new HashMap();

  static {
    catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_I),
        Integers.valueOf(QTESLASecurityCategory.PROVABLY_SECURE_I));
    catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_III),
        Integers.valueOf(QTESLASecurityCategory.PROVABLY_SECURE_III));
  }

  private QTESLAKeyGenerationParameters param;
  private QTESLAKeyPairGenerator engine = new QTESLAKeyPairGenerator();

  private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
  private boolean initialised = false;

  public KeyPairGeneratorSpi() {
    super("qTESLA");
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
    if (!(params instanceof QTESLAParameterSpec)) {
      throw new InvalidAlgorithmParameterException("parameter object not a QTESLAParameterSpec");
    }

    QTESLAParameterSpec qteslaParams = (QTESLAParameterSpec) params;

    param = new QTESLAKeyGenerationParameters(
        ((Integer) catLookup.get(qteslaParams.getSecurityCategory())).intValue(), random);

    engine.init(param);
    initialised = true;
  }

  public KeyPair generateKeyPair() {
    if (!initialised) {
      param = new QTESLAKeyGenerationParameters(QTESLASecurityCategory.PROVABLY_SECURE_III, random);

      engine.init(param);
      initialised = true;
    }

    AsymmetricCipherKeyPair pair = engine.generateKeyPair();
    QTESLAPublicKeyParameters pub = (QTESLAPublicKeyParameters) pair.getPublic();
    QTESLAPrivateKeyParameters priv = (QTESLAPrivateKeyParameters) pair.getPrivate();

    return new KeyPair(new BCqTESLAPublicKey(pub), new BCqTESLAPrivateKey(priv));
  }
}