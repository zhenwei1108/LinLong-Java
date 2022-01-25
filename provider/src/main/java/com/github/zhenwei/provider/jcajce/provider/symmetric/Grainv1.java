package com.github.zhenwei.provider.jcajce.provider.symmetric;

import com.github.zhenwei.core.crypto.CipherKeyGenerator;
import com.github.zhenwei.core.crypto.engines.Grainv1Engine;
import com.github.zhenwei.provider.jcajce.provider.config.ConfigurableProvider;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.BaseStreamCipher;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import com.github.zhenwei.provider.jcajce.provider.util.AlgorithmProvider;

public final class Grainv1 {

  private Grainv1() {
  }

  public static class Base
      extends BaseStreamCipher {

    public Base() {
      super(new Grainv1Engine(), 8);
    }
  }

  public static class KeyGen
      extends BaseKeyGenerator {

    public KeyGen() {
      super("Grainv1", 80, new CipherKeyGenerator());
    }
  }

  public static class AlgParams
      extends IvAlgorithmParameters {

    protected String engineToString() {
      return "Grainv1 IV";
    }
  }

  public static class Mappings
      extends AlgorithmProvider {

    private static final String PREFIX = Grainv1.class.getName();

    public Mappings() {
    }

    public void configure(ConfigurableProvider provider) {
      provider.addAlgorithm("Cipher.Grainv1", PREFIX + "$Base");
      provider.addAlgorithm("KeyGenerator.Grainv1", PREFIX + "$KeyGen");
      provider.addAlgorithm("AlgorithmParameters.Grainv1", PREFIX + "$AlgParams");
    }
  }
}