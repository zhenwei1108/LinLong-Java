package com.github.zhenwei.pkix.its.jcajce;

import com.github.zhenwei.pkix.its.ITSCertificate;
import com.github.zhenwei.pkix.its.ITSImplicitCertificateBuilder;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import com.github.zhenwei.pkix.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import com.github.zhenwei.pkix.util.oer.its.ToBeSignedCertificate;
import java.security.Provider;

public class JcaITSImplicitCertificateBuilderBuilder {

  private JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();

  public JcaITSImplicitCertificateBuilderBuilder setProvider(Provider provider) {
    this.digestCalculatorProviderBuilder.setProvider(provider);

    return this;
  }

  public JcaITSImplicitCertificateBuilderBuilder setProvider(String providerName) {
    this.digestCalculatorProviderBuilder.setProvider(providerName);

    return this;
  }

  public ITSImplicitCertificateBuilder build(ITSCertificate issuer,
      ToBeSignedCertificate.Builder tbsCertificate)
      throws OperatorCreationException {
    return new ITSImplicitCertificateBuilder(issuer, digestCalculatorProviderBuilder.build(),
        tbsCertificate);
  }
}