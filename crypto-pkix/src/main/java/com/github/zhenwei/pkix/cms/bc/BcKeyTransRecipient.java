package com.github.zhenwei.pkix.cms.bc;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.pkix.cms.CMSException;
import com.github.zhenwei.pkix.cms.KeyTransRecipient;
import com.github.zhenwei.pkix.operator.AsymmetricKeyUnwrapper;
import com.github.zhenwei.pkix.operator.OperatorException;
import com.github.zhenwei.pkix.operator.bc.BcRSAAsymmetricKeyUnwrapper;

public abstract class BcKeyTransRecipient
    implements KeyTransRecipient {

  private AsymmetricKeyParameter recipientKey;

  public BcKeyTransRecipient(AsymmetricKeyParameter recipientKey) {
    this.recipientKey = recipientKey;
  }

  protected CipherParameters extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm,
      AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedEncryptionKey)
      throws CMSException {
    AsymmetricKeyUnwrapper unwrapper = new BcRSAAsymmetricKeyUnwrapper(keyEncryptionAlgorithm,
        recipientKey);

    try {
      return CMSUtils.getBcKey(
          unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedEncryptionKey));
    } catch (OperatorException e) {
      throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
    }
  }
}