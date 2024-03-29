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
import java.security.PrivateKey;
import javax.crypto.Mac;


/**
 * the KeyTransRecipientInformation class for a recipient who has been sent a secret key encrypted
 * using their public key that needs to be used to extract the message.
 */
public class JceKeyTransAuthenticatedRecipient
    extends JceKeyTransRecipient {

  public JceKeyTransAuthenticatedRecipient(PrivateKey recipientKey) {
    super(recipientKey);
  }

  public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm,
      final AlgorithmIdentifier contentMacAlgorithm, byte[] encryptedContentEncryptionKey)
      throws CMSException {
    final Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentMacAlgorithm,
        encryptedContentEncryptionKey);

    final Mac dataMac = contentHelper.createContentMac(secretKey, contentMacAlgorithm);

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