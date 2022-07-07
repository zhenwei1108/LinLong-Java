package com.github.zhenwei.provider.jcajce.provider;

import com.github.zhenwei.core.pqc.asn1.PQCObjectIdentifiers;
import com.github.zhenwei.provider.jcajce.provider.config.ConfigurableProvider;
import com.github.zhenwei.provider.jcajce.provider.newhope.NHKeyFactorySpi;
import com.github.zhenwei.provider.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.github.zhenwei.provider.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class NH {

  private static final String PREFIX = "com.github.zhenwei.core.pqc.jcajce.provider" + ".newhope.";

  public static class Mappings
      extends AsymmetricAlgorithmProvider {

    public Mappings() {
    }

    public void configure(ConfigurableProvider provider) {
      provider.addAlgorithm("KeyFactory.NH", PREFIX + "NHKeyFactorySpi");
      provider.addAlgorithm("KeyPairGenerator.NH", PREFIX + "NHKeyPairGeneratorSpi");

      provider.addAlgorithm("KeyAgreement.NH", PREFIX + "KeyAgreementSpi");

      AsymmetricKeyInfoConverter keyFact = new NHKeyFactorySpi();

      registerOid(provider, PQCObjectIdentifiers.newHope, "NH", keyFact);
    }
  }
}