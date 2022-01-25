package com.github.zhenwei.provider.jcajce.provider.asymmetric;

import com.github.zhenwei.provider.jcajce.provider.config.ConfigurableProvider;
import com.github.zhenwei.provider.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class IES {

  private static final String PREFIX =
      "com.github.zhenwei.provider.jcajce.provider.asymmetric" + ".ies.";

  public static class Mappings
      extends AsymmetricAlgorithmProvider {

    public Mappings() {
    }

    public void configure(ConfigurableProvider provider) {
      provider.addAlgorithm("AlgorithmParameters.IES", PREFIX + "AlgorithmParametersSpi");
      provider.addAlgorithm("AlgorithmParameters.ECIES", PREFIX + "AlgorithmParametersSpi");
    }
  }
}