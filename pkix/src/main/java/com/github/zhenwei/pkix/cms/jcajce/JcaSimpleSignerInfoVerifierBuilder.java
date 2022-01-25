package com.github.zhenwei.pkix.cms.jcajce;

import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import com.github.zhenwei.pkix.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import com.github.zhenwei.pkix.cms.SignerInformationVerifier;
import com.github.zhenwei.pkix.operator.ContentVerifierProvider;
import com.github.zhenwei.pkix.operator.DefaultSignatureAlgorithmIdentifierFinder;
import com.github.zhenwei.pkix.operator.DigestCalculatorProvider;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import com.github.zhenwei.pkix.operator.jcajce.JcaContentVerifierProviderBuilder;
import com.github.zhenwei.pkix.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class JcaSimpleSignerInfoVerifierBuilder {

  private Helper helper = new Helper();

  public JcaSimpleSignerInfoVerifierBuilder setProvider(Provider provider) {
    this.helper = new ProviderHelper(provider);

    return this;
  }

  public JcaSimpleSignerInfoVerifierBuilder setProvider(String providerName) {
    this.helper = new NamedHelper(providerName);

    return this;
  }

  public SignerInformationVerifier build(X509CertificateHolder certHolder)
      throws OperatorCreationException, CertificateException {
    return new SignerInformationVerifier(new DefaultCMSSignatureAlgorithmNameGenerator(),
        new DefaultSignatureAlgorithmIdentifierFinder(),
        helper.createContentVerifierProvider(certHolder), helper.createDigestCalculatorProvider());
  }

  public SignerInformationVerifier build(X509Certificate certificate)
      throws OperatorCreationException {
    return new SignerInformationVerifier(new DefaultCMSSignatureAlgorithmNameGenerator(),
        new DefaultSignatureAlgorithmIdentifierFinder(),
        helper.createContentVerifierProvider(certificate), helper.createDigestCalculatorProvider());
  }

  public SignerInformationVerifier build(PublicKey pubKey)
      throws OperatorCreationException {
    return new SignerInformationVerifier(new DefaultCMSSignatureAlgorithmNameGenerator(),
        new DefaultSignatureAlgorithmIdentifierFinder(),
        helper.createContentVerifierProvider(pubKey), helper.createDigestCalculatorProvider());
  }

  private class Helper {

    ContentVerifierProvider createContentVerifierProvider(PublicKey publicKey)
        throws OperatorCreationException {
      return new JcaContentVerifierProviderBuilder().build(publicKey);
    }

    ContentVerifierProvider createContentVerifierProvider(X509Certificate certificate)
        throws OperatorCreationException {
      return new JcaContentVerifierProviderBuilder().build(certificate);
    }

    ContentVerifierProvider createContentVerifierProvider(X509CertificateHolder certHolder)
        throws OperatorCreationException, CertificateException {
      return new JcaContentVerifierProviderBuilder().build(certHolder);
    }

    DigestCalculatorProvider createDigestCalculatorProvider()
        throws OperatorCreationException {
      return new JcaDigestCalculatorProviderBuilder().build();
    }
  }

  private class NamedHelper
      extends Helper {

    private final String providerName;

    public NamedHelper(String providerName) {
      this.providerName = providerName;
    }

    ContentVerifierProvider createContentVerifierProvider(PublicKey publicKey)
        throws OperatorCreationException {
      return new JcaContentVerifierProviderBuilder().setProvider(providerName).build(publicKey);
    }

    ContentVerifierProvider createContentVerifierProvider(X509Certificate certificate)
        throws OperatorCreationException {
      return new JcaContentVerifierProviderBuilder().setProvider(providerName).build(certificate);
    }

    DigestCalculatorProvider createDigestCalculatorProvider()
        throws OperatorCreationException {
      return new JcaDigestCalculatorProviderBuilder().setProvider(providerName).build();
    }

    ContentVerifierProvider createContentVerifierProvider(X509CertificateHolder certHolder)
        throws OperatorCreationException, CertificateException {
      return new JcaContentVerifierProviderBuilder().setProvider(providerName).build(certHolder);
    }
  }

  private class ProviderHelper
      extends Helper {

    private final Provider provider;

    public ProviderHelper(Provider provider) {
      this.provider = provider;
    }

    ContentVerifierProvider createContentVerifierProvider(PublicKey publicKey)
        throws OperatorCreationException {
      return new JcaContentVerifierProviderBuilder().setProvider(provider).build(publicKey);
    }

    ContentVerifierProvider createContentVerifierProvider(X509Certificate certificate)
        throws OperatorCreationException {
      return new JcaContentVerifierProviderBuilder().setProvider(provider).build(certificate);
    }

    DigestCalculatorProvider createDigestCalculatorProvider()
        throws OperatorCreationException {
      return new JcaDigestCalculatorProviderBuilder().setProvider(provider).build();
    }

    ContentVerifierProvider createContentVerifierProvider(X509CertificateHolder certHolder)
        throws OperatorCreationException, CertificateException {
      return new JcaContentVerifierProviderBuilder().setProvider(provider).build(certHolder);
    }
  }
}