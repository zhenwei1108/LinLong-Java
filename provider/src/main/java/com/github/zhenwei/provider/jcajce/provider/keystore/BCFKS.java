package com.github.zhenwei.provider.jcajce.provider.keystore;

import com.github.zhenwei.provider.jcajce.provider.config.ConfigurableProvider;
import com.github.zhenwei.provider.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class BCFKS {

  private static final String PREFIX =
      "com.github.zhenwei.provider.jcajce.provider.keystore" + ".bcfks.";

  public static class Mappings
      extends AsymmetricAlgorithmProvider {

    public Mappings() {
    }

    public void configure(ConfigurableProvider provider) {
      provider.addAlgorithm("KeyStore.BCFKS", PREFIX + "BcFKSKeyStoreSpi$Std");
      provider.addAlgorithm("KeyStore.BCFKS-DEF", PREFIX + "BcFKSKeyStoreSpi$Def");

      provider.addAlgorithm("KeyStore.FIPS", PREFIX + "BcFKSKeyStoreSpi$StdCompat");
      provider.addAlgorithm("KeyStore.FIPS-DEF", PREFIX + "BcFKSKeyStoreSpi$DefCompat");

      provider.addAlgorithm("KeyStore.IBCFKS", PREFIX + "BcFKSKeyStoreSpi$StdShared");
      provider.addAlgorithm("KeyStore.IBCFKS-DEF", PREFIX + "BcFKSKeyStoreSpi$DefShared");

      provider.addAlgorithm("KeyStore.IFIPS", PREFIX + "BcFKSKeyStoreSpi$StdSharedCompat");
      provider.addAlgorithm("KeyStore.IFIPS-DEF", PREFIX + "BcFKSKeyStoreSpi$DefSharedCompat");
    }
  }
}