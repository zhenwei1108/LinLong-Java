package com.github.zhenwei.provider.jcajce.provider.digest;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.provider.jcajce.provider.config.ConfigurableProvider;
import com.github.zhenwei.provider.jcajce.provider.util.AlgorithmProvider;

abstract class DigestAlgorithmProvider
    extends AlgorithmProvider {

  protected void addHMACAlgorithm(
      ConfigurableProvider provider,
      String algorithm,
      String algorithmClassName,
      String keyGeneratorClassName) {
    String mainName = "HMAC" + algorithm;

    provider.addAlgorithm("Mac." + mainName, algorithmClassName);
    provider.addAlgorithm("Alg.Alias.Mac.HMAC-" + algorithm, mainName);
    provider.addAlgorithm("Alg.Alias.Mac.HMAC/" + algorithm, mainName);
    provider.addAlgorithm("KeyGenerator." + mainName, keyGeneratorClassName);
    provider.addAlgorithm("Alg.Alias.KeyGenerator.HMAC-" + algorithm, mainName);
    provider.addAlgorithm("Alg.Alias.KeyGenerator.HMAC/" + algorithm, mainName);
  }

  protected void addHMACAlias(
      ConfigurableProvider provider,
      String algorithm,
      ASN1ObjectIdentifier oid) {
    String mainName = "HMAC" + algorithm;

    provider.addAlgorithm("Alg.Alias.Mac." + oid, mainName);
    provider.addAlgorithm("Alg.Alias.KeyGenerator." + oid, mainName);
  }
}