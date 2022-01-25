package com.github.zhenwei.pkix.cms.jcajce;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.cms.CMSException;
import com.github.zhenwei.pkix.cms.RecipientOperator;
import com.github.zhenwei.pkix.operator.InputDecryptor;
import com.github.zhenwei.provider.jcajce.io.CipherInputStream;
import java.io.InputStream;
import java.security.Key;
import javax.crypto.Cipher;

public class JcePasswordEnvelopedRecipient
    extends JcePasswordRecipient {

  public JcePasswordEnvelopedRecipient(char[] password) {
    super(password);
  }

  public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm,
      final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] derivedKey,
      byte[] encryptedContentEncryptionKey)
      throws CMSException {
    Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, derivedKey,
        encryptedContentEncryptionKey);

    final Cipher dataCipher = helper.createContentCipher(secretKey, contentEncryptionAlgorithm);

    return new RecipientOperator(new InputDecryptor() {
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return contentEncryptionAlgorithm;
      }

      public InputStream getInputStream(InputStream dataOut) {
        return new CipherInputStream(dataOut, dataCipher);
      }
    });
  }
}