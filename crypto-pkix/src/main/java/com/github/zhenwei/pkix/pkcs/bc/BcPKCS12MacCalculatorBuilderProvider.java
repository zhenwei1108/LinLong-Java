package com.github.zhenwei.pkix.pkcs.bc;

import com.github.zhenwei.core.asn1.DERNull;
import com.github.zhenwei.core.asn1.pkcs.PKCS12PBEParams;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.operator.MacCalculator;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import com.github.zhenwei.pkix.operator.bc.BcDigestProvider;
import com.github.zhenwei.pkix.pkcs.PKCS12MacCalculatorBuilder;
import com.github.zhenwei.pkix.pkcs.PKCS12MacCalculatorBuilderProvider;

public class BcPKCS12MacCalculatorBuilderProvider
    implements PKCS12MacCalculatorBuilderProvider {

  private BcDigestProvider digestProvider;

  public BcPKCS12MacCalculatorBuilderProvider(BcDigestProvider digestProvider) {
    this.digestProvider = digestProvider;
  }

  public PKCS12MacCalculatorBuilder get(final AlgorithmIdentifier algorithmIdentifier) {
    return new PKCS12MacCalculatorBuilder() {
      public MacCalculator build(final char[] password)
          throws OperatorCreationException {
        PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(
            algorithmIdentifier.getParameters());

        return PKCS12PBEUtils.createMacCalculator(algorithmIdentifier.getAlgorithm(),
            digestProvider.get(algorithmIdentifier), pbeParams, password);
      }

      public AlgorithmIdentifier getDigestAlgorithmIdentifier() {
        return new AlgorithmIdentifier(algorithmIdentifier.getAlgorithm(), DERNull.INSTANCE);
      }
    };
  }
}