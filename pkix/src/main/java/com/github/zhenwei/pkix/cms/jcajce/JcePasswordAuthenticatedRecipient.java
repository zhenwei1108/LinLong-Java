package com.github.zhenwei.pkix.cms.jcajce;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.cms.CMSException;
import com.github.zhenwei.pkix.cms.RecipientOperator;
import com.github.zhenwei.pkix.operator.GenericKey;
import com.github.zhenwei.pkix.operator.MacCalculator;
import com.github.zhenwei.pkix.operator.jcajce.JceGenericKey;
import com.github.zhenwei.provider.jcajce.io.MacOutputStream;
import java.io.OutputStream;
import java.security.Key;
import javax.crypto.Mac;

public class JcePasswordAuthenticatedRecipient
    extends JcePasswordRecipient {

  public JcePasswordAuthenticatedRecipient(char[] password) {
    super(password);
  }

  public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm,
      final AlgorithmIdentifier contentMacAlgorithm, byte[] derivedKey,
      byte[] encryptedContentEncryptionKey)
      throws CMSException {
    final Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentMacAlgorithm, derivedKey,
        encryptedContentEncryptionKey);

    final Mac dataMac = helper.createContentMac(secretKey, contentMacAlgorithm);

    return new RecipientOperator(new MacCalculator() {
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return contentMacAlgorithm;
      }

      public GenericKey getKey() {
        return new JceGenericKey(contentMacAlgorithm, secretKey);
      }

      public OutputStream getOutputStream() {
        return new MacOutputStream(dataMac);
      }

      public byte[] getMac() {
        return dataMac.doFinal();
      }
    });
  }
}