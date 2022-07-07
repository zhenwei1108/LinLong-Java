package com.github.zhenwei.pkix.cms.bc;

import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import com.github.zhenwei.pkix.cms.CMSSignatureAlgorithmNameGenerator;
import com.github.zhenwei.pkix.cms.SignerInformationVerifier;
import com.github.zhenwei.pkix.operator.DigestAlgorithmIdentifierFinder;
import com.github.zhenwei.pkix.operator.DigestCalculatorProvider;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import com.github.zhenwei.pkix.operator.SignatureAlgorithmIdentifierFinder;
import com.github.zhenwei.pkix.operator.bc.BcECContentVerifierProviderBuilder;

public class BcECSignerInfoVerifierBuilder {

  private BcECContentVerifierProviderBuilder contentVerifierProviderBuilder;
  private DigestCalculatorProvider digestCalculatorProvider;
  private CMSSignatureAlgorithmNameGenerator sigAlgNameGen;
  private SignatureAlgorithmIdentifierFinder sigAlgIdFinder;

  public BcECSignerInfoVerifierBuilder(CMSSignatureAlgorithmNameGenerator sigAlgNameGen,
      SignatureAlgorithmIdentifierFinder sigAlgIdFinder,
      DigestAlgorithmIdentifierFinder digestAlgorithmFinder,
      DigestCalculatorProvider digestCalculatorProvider) {
    this.sigAlgNameGen = sigAlgNameGen;
    this.sigAlgIdFinder = sigAlgIdFinder;
    this.contentVerifierProviderBuilder = new BcECContentVerifierProviderBuilder(
        digestAlgorithmFinder);
    this.digestCalculatorProvider = digestCalculatorProvider;
  }

  public SignerInformationVerifier build(X509CertificateHolder certHolder)
      throws OperatorCreationException {
    return new SignerInformationVerifier(sigAlgNameGen, sigAlgIdFinder,
        contentVerifierProviderBuilder.build(certHolder), digestCalculatorProvider);
  }

  public SignerInformationVerifier build(AsymmetricKeyParameter pubKey)
      throws OperatorCreationException {
    return new SignerInformationVerifier(sigAlgNameGen, sigAlgIdFinder,
        contentVerifierProviderBuilder.build(pubKey), digestCalculatorProvider);
  }
}