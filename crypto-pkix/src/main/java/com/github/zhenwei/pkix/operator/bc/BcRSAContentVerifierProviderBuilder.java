package com.github.zhenwei.pkix.operator.bc;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.crypto.Signer;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.signers.RSADigestSigner;
import com.github.zhenwei.core.crypto.util.PublicKeyFactory;
import com.github.zhenwei.pkix.operator.DigestAlgorithmIdentifierFinder;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import java.io.IOException;

public class BcRSAContentVerifierProviderBuilder
    extends BcContentVerifierProviderBuilder {

  private DigestAlgorithmIdentifierFinder digestAlgorithmFinder;

  public BcRSAContentVerifierProviderBuilder(
      DigestAlgorithmIdentifierFinder digestAlgorithmFinder) {
    this.digestAlgorithmFinder = digestAlgorithmFinder;
  }

  protected Signer createSigner(AlgorithmIdentifier sigAlgId)
      throws OperatorCreationException {
    AlgorithmIdentifier digAlg = digestAlgorithmFinder.find(sigAlgId);
    Digest dig = digestProvider.get(digAlg);

    return new RSADigestSigner(dig);
  }

  protected AsymmetricKeyParameter extractKeyParameters(SubjectPublicKeyInfo publicKeyInfo)
      throws IOException {
    return PublicKeyFactory.createKey(publicKeyInfo);
  }
}