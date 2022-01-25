package com.github.zhenwei.pkix.operator.bc;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.AsymmetricBlockCipher;
import com.github.zhenwei.core.crypto.encodings.PKCS1Encoding;
import com.github.zhenwei.core.crypto.engines.RSABlindedEngine;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;

public class BcRSAAsymmetricKeyUnwrapper
    extends BcAsymmetricKeyUnwrapper {

  public BcRSAAsymmetricKeyUnwrapper(AlgorithmIdentifier encAlgId,
      AsymmetricKeyParameter privateKey) {
    super(encAlgId, privateKey);
  }

  protected AsymmetricBlockCipher createAsymmetricUnwrapper(ASN1ObjectIdentifier algorithm) {
    return new PKCS1Encoding(new RSABlindedEngine());
  }
}