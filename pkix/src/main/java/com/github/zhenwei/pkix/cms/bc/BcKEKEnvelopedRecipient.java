package com.github.zhenwei.pkix.cms.bc;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.BufferedBlockCipher;
import com.github.zhenwei.core.crypto.StreamCipher;
import com.github.zhenwei.core.crypto.params.KeyParameter;
import com.github.zhenwei.pkix.cms.CMSException;
import com.github.zhenwei.pkix.cms.RecipientOperator;
import com.github.zhenwei.pkix.operator.InputDecryptor;
import com.github.zhenwei.pkix.operator.bc.BcSymmetricKeyUnwrapper;
import java.io.InputStream;

public class BcKEKEnvelopedRecipient
    extends BcKEKRecipient {

  public BcKEKEnvelopedRecipient(BcSymmetricKeyUnwrapper unwrapper) {
    super(unwrapper);
  }

  public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm,
      final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
      throws CMSException {
    KeyParameter secretKey = (KeyParameter) extractSecretKey(keyEncryptionAlgorithm,
        contentEncryptionAlgorithm, encryptedContentEncryptionKey);

    final Object dataCipher = EnvelopedDataHelper.createContentCipher(false, secretKey,
        contentEncryptionAlgorithm);

    return new RecipientOperator(new InputDecryptor() {
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return contentEncryptionAlgorithm;
      }

      public InputStream getInputStream(InputStream dataOut) {
        if (dataCipher instanceof BufferedBlockCipher) {
          return new com.github.zhenwei.core.crypto.io.CipherInputStream(dataOut,
              (BufferedBlockCipher) dataCipher);
        } else {
          return new com.github.zhenwei.core.crypto.io.CipherInputStream(dataOut,
              (StreamCipher) dataCipher);
        }
      }
    });
  }
}