package com.github.zhenwei.pkix.operator.bc;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.AsymmetricBlockCipher;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.InvalidCipherTextException;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.params.ParametersWithRandom;
import com.github.zhenwei.pkix.operator.AsymmetricKeyWrapper;
import com.github.zhenwei.pkix.operator.GenericKey;
import com.github.zhenwei.pkix.operator.OperatorException;
import java.security.SecureRandom;

public abstract class BcAsymmetricKeyWrapper
    extends AsymmetricKeyWrapper {

  private AsymmetricKeyParameter publicKey;
  private SecureRandom random;

  public BcAsymmetricKeyWrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter publicKey) {
    super(encAlgId);

    this.publicKey = publicKey;
  }

  public BcAsymmetricKeyWrapper setSecureRandom(SecureRandom random) {
    this.random = random;

    return this;
  }

  public byte[] generateWrappedKey(GenericKey encryptionKey)
      throws OperatorException {
    AsymmetricBlockCipher keyEncryptionCipher = createAsymmetricWrapper(
        getAlgorithmIdentifier().getAlgorithm());

    CipherParameters params = publicKey;
    if (random != null) {
      params = new ParametersWithRandom(params, random);
    }

    try {
      byte[] keyEnc = OperatorUtils.getKeyBytes(encryptionKey);
      keyEncryptionCipher.init(true, params);
      return keyEncryptionCipher.processBlock(keyEnc, 0, keyEnc.length);
    } catch (InvalidCipherTextException e) {
      throw new OperatorException("unable to encrypt contents key", e);
    }
  }

  protected abstract AsymmetricBlockCipher createAsymmetricWrapper(ASN1ObjectIdentifier algorithm);
}