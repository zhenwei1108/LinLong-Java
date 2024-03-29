package com.github.zhenwei.pkix.cms.bc;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.BufferedBlockCipher;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.StreamCipher;
import com.github.zhenwei.core.crypto.io.CipherInputStream;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.pkix.cms.CMSException;
import com.github.zhenwei.pkix.cms.RecipientOperator;
import com.github.zhenwei.pkix.operator.InputDecryptor;
import java.io.InputStream;

public class BcRSAKeyTransEnvelopedRecipient
    extends BcKeyTransRecipient {

  public BcRSAKeyTransEnvelopedRecipient(AsymmetricKeyParameter key) {
    super(key);
  }

  public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm,
      final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
      throws CMSException {
    CipherParameters secretKey = extractSecretKey(keyEncryptionAlgorithm,
        contentEncryptionAlgorithm, encryptedContentEncryptionKey);

    final Object dataCipher = EnvelopedDataHelper.createContentCipher(false, secretKey,
        contentEncryptionAlgorithm);

    return new RecipientOperator(new InputDecryptor() {
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return contentEncryptionAlgorithm;
      }

      public InputStream getInputStream(InputStream dataIn) {
        if (dataCipher instanceof BufferedBlockCipher) {
          return new CipherInputStream(dataIn, (BufferedBlockCipher) dataCipher);
        } else {
          return new CipherInputStream(dataIn, (StreamCipher) dataCipher);
        }
      }
    });
  }
}