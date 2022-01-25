package com.github.zhenwei.pkix.operator.jcajce;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.operator.GenericKey;
import com.github.zhenwei.pkix.operator.OperatorException;
import com.github.zhenwei.pkix.operator.SymmetricKeyUnwrapper;
import com.github.zhenwei.provider.jcajce.util.DefaultJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.NamedJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.ProviderJcaJceHelper;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class JceSymmetricKeyUnwrapper
    extends SymmetricKeyUnwrapper {

  private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
  private SecretKey secretKey;

  public JceSymmetricKeyUnwrapper(AlgorithmIdentifier algorithmIdentifier, SecretKey secretKey) {
    super(algorithmIdentifier);

    this.secretKey = secretKey;
  }

  public JceSymmetricKeyUnwrapper setProvider(Provider provider) {
    this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

    return this;
  }

  public JceSymmetricKeyUnwrapper setProvider(String providerName) {
    this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

    return this;
  }

  public GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm,
      byte[] encryptedKey)
      throws OperatorException {
    try {
      Cipher keyCipher = helper.createSymmetricWrapper(
          this.getAlgorithmIdentifier().getAlgorithm());

      keyCipher.init(Cipher.UNWRAP_MODE, secretKey);

      return new JceGenericKey(encryptedKeyAlgorithm, keyCipher.unwrap(encryptedKey,
          helper.getKeyAlgorithmName(encryptedKeyAlgorithm.getAlgorithm()), Cipher.SECRET_KEY));
    } catch (InvalidKeyException e) {
      throw new OperatorException("key invalid in message.", e);
    } catch (NoSuchAlgorithmException e) {
      throw new OperatorException("can't find algorithm.", e);
    }
  }
}