package com.github.zhenwei.pkix.operator.bc;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.crypto.Signer;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.signers.DSADigestSigner;
import com.github.zhenwei.core.crypto.signers.DSASigner;
import com.github.zhenwei.core.crypto.util.PublicKeyFactory;
import com.github.zhenwei.pkix.operator.DigestAlgorithmIdentifierFinder;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import java.io.IOException;

public class BcDSAContentVerifierProviderBuilder
    extends BcContentVerifierProviderBuilder {

  private DigestAlgorithmIdentifierFinder digestAlgorithmFinder;

  public BcDSAContentVerifierProviderBuilder(
      DigestAlgorithmIdentifierFinder digestAlgorithmFinder) {
    this.digestAlgorithmFinder = digestAlgorithmFinder;
  }

  protected Signer createSigner(AlgorithmIdentifier sigAlgId)
      throws OperatorCreationException {
    AlgorithmIdentifier digAlg = digestAlgorithmFinder.find(sigAlgId);
    Digest dig = digestProvider.get(digAlg);

    return new DSADigestSigner(new DSASigner(), dig);
  }

  protected AsymmetricKeyParameter extractKeyParameters(SubjectPublicKeyInfo publicKeyInfo)
      throws IOException {
    return PublicKeyFactory.createKey(publicKeyInfo);
  }
}