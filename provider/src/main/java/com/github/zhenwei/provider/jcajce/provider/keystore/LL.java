package com.github.zhenwei.provider.jcajce.provider.keystore;

import com.github.zhenwei.provider.jcajce.provider.config.ConfigurableProvider;
import com.github.zhenwei.provider.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class LL {

  private static final String PREFIX =
      "com.github.zhenwei.provider.jcajce.provider.keystore" + ".bc.";

  public static class Mappings
      extends AsymmetricAlgorithmProvider {

    public Mappings() {
    }

    public void configure(ConfigurableProvider provider) {
      provider.addAlgorithm("KeyStore.LL", PREFIX + "BcKeyStoreSpi$Std");
//
//      if (Properties.isOverrideSet("org.bouncycastle.bks.enable_v1")) {
//        provider.addAlgorithm("KeyStore.LL-V1", PREFIX + "BcKeyStoreSpi$Version1");
//      }
//
//      provider.addAlgorithm("KeyStore.BouncyCastle", PREFIX + "BcKeyStoreSpi$BouncyCastleStore");
//      provider.addAlgorithm("Alg.Alias.KeyStore.UBER", "BouncyCastle");
//      provider.addAlgorithm("Alg.Alias.KeyStore.BOUNCYCASTLE", "BouncyCastle");
//      provider.addAlgorithm("Alg.Alias.KeyStore.bouncycastle", "BouncyCastle");
    }
  }
}