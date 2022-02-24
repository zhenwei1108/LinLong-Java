package com.github.zhenwei.pkix.operator.bc;

import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.crypto.Signer;
import com.github.zhenwei.core.crypto.digests.SM3Digest;
import com.github.zhenwei.core.crypto.signers.DSADigestSigner;
import com.github.zhenwei.core.crypto.signers.ECDSASigner;
import com.github.zhenwei.core.crypto.signers.SM2Signer;
import com.github.zhenwei.pkix.operator.OperatorCreationException;

public class BcECContentSignerBuilder
    extends BcContentSignerBuilder {

  public BcECContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId) {
    super(sigAlgId, digAlgId);
  }

  protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
      throws OperatorCreationException {
    Digest dig = digestProvider.get(digAlgId);
    //SM3WithSM2 算法使用固定 UID, 公钥参与摘要运算
    if (dig instanceof SM3Digest && sigAlgId.getAlgorithm().equals(GMObjectIdentifiers.sm2sign_with_sm3)){
      return new SM2Signer(dig);
    }
    return new DSADigestSigner(new ECDSASigner(), dig);
  }
}