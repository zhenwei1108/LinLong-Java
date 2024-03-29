package com.github.zhenwei.provider.jcajce.provider;

import com.github.zhenwei.core.pqc.asn1.PQCObjectIdentifiers;
import com.github.zhenwei.provider.jcajce.provider.config.ConfigurableProvider;
import com.github.zhenwei.provider.jcajce.provider.rainbow.RainbowKeyFactorySpi;
import com.github.zhenwei.provider.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.github.zhenwei.provider.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class Rainbow {

  private static final String PREFIX = "com.github.zhenwei.core.pqc.jcajce.provider" + ".rainbow.";

  public static class Mappings
      extends AsymmetricAlgorithmProvider {

    public Mappings() {
    }

    public void configure(ConfigurableProvider provider) {
      provider.addAlgorithm("KeyFactory.Rainbow", PREFIX + "RainbowKeyFactorySpi");
      provider.addAlgorithm("KeyPairGenerator.Rainbow", PREFIX + "RainbowKeyPairGeneratorSpi");

      addSignatureAlgorithm(provider, "SHA224", "Rainbow", PREFIX + "SignatureSpi$withSha224",
          PQCObjectIdentifiers.rainbowWithSha224);
      addSignatureAlgorithm(provider, "SHA256", "Rainbow", PREFIX + "SignatureSpi$withSha256",
          PQCObjectIdentifiers.rainbowWithSha256);
      addSignatureAlgorithm(provider, "SHA384", "Rainbow", PREFIX + "SignatureSpi$withSha384",
          PQCObjectIdentifiers.rainbowWithSha384);
      addSignatureAlgorithm(provider, "SHA512", "Rainbow", PREFIX + "SignatureSpi$withSha512",
          PQCObjectIdentifiers.rainbowWithSha512);

      AsymmetricKeyInfoConverter keyFact = new RainbowKeyFactorySpi();

      registerOid(provider, PQCObjectIdentifiers.rainbow, "Rainbow", keyFact);
    }
  }
}