package com.github.zhenwei.pkix.cms.jcajce;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.cms.CMSException;
import com.github.zhenwei.pkix.cms.RecipientOperator;
import com.github.zhenwei.pkix.operator.InputDecryptor;
import com.github.zhenwei.provider.jcajce.io.CipherInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.PrivateKey;
import javax.crypto.Cipher;

public class JceKeyTransEnvelopedRecipient
    extends JceKeyTransRecipient {

  public JceKeyTransEnvelopedRecipient(PrivateKey recipientKey) {
    super(recipientKey);
  }

  public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm,
      final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
      throws CMSException {
    Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm,
        encryptedContentEncryptionKey);

    final Cipher dataCipher = contentHelper.createContentCipher(secretKey,
        contentEncryptionAlgorithm);

    return new RecipientOperator(new InputDecryptor() {
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return contentEncryptionAlgorithm;
      }

      public InputStream getInputStream(InputStream dataIn) {
        return new CipherInputStream(dataIn, dataCipher);
      }
    });
  }
}