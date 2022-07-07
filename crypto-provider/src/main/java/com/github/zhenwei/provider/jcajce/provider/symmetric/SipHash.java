package com.github.zhenwei.provider.jcajce.provider.symmetric;

import com.github.zhenwei.core.crypto.CipherKeyGenerator;
import com.github.zhenwei.provider.jcajce.provider.config.ConfigurableProvider;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.BaseMac;
import com.github.zhenwei.provider.jcajce.provider.util.AlgorithmProvider;

public final class SipHash {

  private SipHash() {
  }

  public static class Mac24
      extends BaseMac {

    public Mac24() {
      super(new com.github.zhenwei.core.crypto.macs.SipHash());
    }
  }

  public static class Mac48
      extends BaseMac {

    public Mac48() {
      super(new com.github.zhenwei.core.crypto.macs.SipHash(4, 8));
    }
  }

  public static class KeyGen
      extends BaseKeyGenerator {

    public KeyGen() {
      super("SipHash", 128, new CipherKeyGenerator());
    }
  }

  public static class Mappings
      extends AlgorithmProvider {

    private static final String PREFIX = SipHash.class.getName();

    public Mappings() {
    }

    public void configure(ConfigurableProvider provider) {
      provider.addAlgorithm("Mac.SIPHASH-2-4", PREFIX + "$Mac24");
      provider.addAlgorithm("Alg.Alias.Mac.SIPHASH", "SIPHASH-2-4");
      provider.addAlgorithm("Mac.SIPHASH-4-8", PREFIX + "$Mac48");

      provider.addAlgorithm("KeyGenerator.SIPHASH", PREFIX + "$KeyGen");
      provider.addAlgorithm("Alg.Alias.KeyGenerator.SIPHASH-2-4", "SIPHASH");
      provider.addAlgorithm("Alg.Alias.KeyGenerator.SIPHASH-4-8", "SIPHASH");
    }
  }
}