package com.github.zhenwei.pkix.operator.bc;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.crypto.AsymmetricBlockCipher;
import com.github.zhenwei.core.crypto.encodings.PKCS1Encoding;
import com.github.zhenwei.core.crypto.engines.RSABlindedEngine;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.util.PublicKeyFactory;
import java.io.IOException;

public class BcRSAAsymmetricKeyWrapper
    extends BcAsymmetricKeyWrapper {

  public BcRSAAsymmetricKeyWrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter publicKey) {
    super(encAlgId, publicKey);
  }

  public BcRSAAsymmetricKeyWrapper(AlgorithmIdentifier encAlgId, SubjectPublicKeyInfo publicKeyInfo)
      throws IOException {
    super(encAlgId, PublicKeyFactory.createKey(publicKeyInfo));
  }

  protected AsymmetricBlockCipher createAsymmetricWrapper(ASN1ObjectIdentifier algorithm) {
    return new PKCS1Encoding(new RSABlindedEngine());
  }
}