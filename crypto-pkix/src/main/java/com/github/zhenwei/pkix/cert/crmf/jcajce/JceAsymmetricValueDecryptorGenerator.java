package com.github.zhenwei.pkix.cert.crmf.jcajce;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.cert.crmf.CRMFException;
import com.github.zhenwei.pkix.cert.crmf.ValueDecryptorGenerator;
import com.github.zhenwei.pkix.operator.InputDecryptor;
import com.github.zhenwei.pkix.operator.OperatorException;
import com.github.zhenwei.pkix.operator.jcajce.JceAsymmetricKeyUnwrapper;
import com.github.zhenwei.provider.jcajce.io.CipherInputStream;
import com.github.zhenwei.provider.jcajce.util.DefaultJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.NamedJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.ProviderJcaJceHelper;
import java.io.InputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class JceAsymmetricValueDecryptorGenerator
    implements ValueDecryptorGenerator {

  private PrivateKey recipientKey;
  private CRMFHelper helper = new CRMFHelper(new DefaultJcaJceHelper());
  private Provider provider = null;
  private String providerName = null;

  public JceAsymmetricValueDecryptorGenerator(PrivateKey recipientKey) {
    this.recipientKey = recipientKey;
  }

  public JceAsymmetricValueDecryptorGenerator setProvider(Provider provider) {
    this.helper = new CRMFHelper(new ProviderJcaJceHelper(provider));
    this.provider = provider;
    this.providerName = null;

    return this;
  }

  public JceAsymmetricValueDecryptorGenerator setProvider(String providerName) {
    this.helper = new CRMFHelper(new NamedJcaJceHelper(providerName));
    this.provider = null;
    this.providerName = providerName;

    return this;
  }

  private Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm,
      AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
      throws CRMFException {
    try {
      JceAsymmetricKeyUnwrapper unwrapper = new JceAsymmetricKeyUnwrapper(keyEncryptionAlgorithm,
          recipientKey);
      if (provider != null) {
        unwrapper.setProvider(provider);
      }
      if (providerName != null) {
        unwrapper.setProvider(providerName);
      }

      return new SecretKeySpec((byte[]) unwrapper.generateUnwrappedKey(contentEncryptionAlgorithm,
          encryptedContentEncryptionKey).getRepresentation(),
          contentEncryptionAlgorithm.getAlgorithm().getId());
    } catch (OperatorException e) {
      throw new CRMFException("key invalid in message: " + e.getMessage(), e);
    }
  }

  public InputDecryptor getValueDecryptor(AlgorithmIdentifier keyEncryptionAlgorithm,
      final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
      throws CRMFException {
    Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm,
        encryptedContentEncryptionKey);

    final Cipher dataCipher = helper.createContentCipher(secretKey, contentEncryptionAlgorithm);

    return new InputDecryptor() {
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return contentEncryptionAlgorithm;
      }

      public InputStream getInputStream(InputStream dataIn) {
        return new CipherInputStream(dataIn, dataCipher);
      }
    };
  }
}