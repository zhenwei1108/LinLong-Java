package com.github.zhenwei.pkix.operator.bc;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.crypto.Signer;
import com.github.zhenwei.core.crypto.signers.DSADigestSigner;
import com.github.zhenwei.core.crypto.signers.DSASigner;
import com.github.zhenwei.pkix.operator.OperatorCreationException;

public class BcDSAContentSignerBuilder
    extends BcContentSignerBuilder {

  public BcDSAContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId) {
    super(sigAlgId, digAlgId);
  }

  protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
      throws OperatorCreationException {
    Digest dig = digestProvider.get(digAlgId);

    return new DSADigestSigner(new DSASigner(), dig);
  }
}