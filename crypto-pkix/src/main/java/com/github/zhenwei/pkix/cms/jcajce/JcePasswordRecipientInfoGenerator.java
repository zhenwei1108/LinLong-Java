package com.github.zhenwei.pkix.cms.jcajce;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.cms.CMSException;
import com.github.zhenwei.pkix.cms.PasswordRecipientInfoGenerator;
import com.github.zhenwei.pkix.operator.GenericKey;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.Provider;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class JcePasswordRecipientInfoGenerator
    extends PasswordRecipientInfoGenerator {

  private EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());

  public JcePasswordRecipientInfoGenerator(ASN1ObjectIdentifier kekAlgorithm, char[] password) {
    super(kekAlgorithm, password);
  }

  public JcePasswordRecipientInfoGenerator setProvider(Provider provider) {
    this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

    return this;
  }

  public JcePasswordRecipientInfoGenerator setProvider(String providerName) {
    this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

    return this;
  }

  protected byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm,
      int keySize)
      throws CMSException {
    return helper.calculateDerivedKey(schemeID, password, derivationAlgorithm, keySize);
  }

  public byte[] generateEncryptedBytes(AlgorithmIdentifier keyEncryptionAlgorithm,
      byte[] derivedKey, GenericKey contentEncryptionKey)
      throws CMSException {
    Key contentEncryptionKeySpec = helper.getJceKey(contentEncryptionKey);
    Cipher keyEncryptionCipher = helper.createRFC3211Wrapper(keyEncryptionAlgorithm.getAlgorithm());

    try {
      IvParameterSpec ivSpec = new IvParameterSpec(
          ASN1OctetString.getInstance(keyEncryptionAlgorithm.getParameters()).getOctets());

      keyEncryptionCipher.init(Cipher.WRAP_MODE,
          new SecretKeySpec(derivedKey, keyEncryptionCipher.getAlgorithm()), ivSpec);

      return keyEncryptionCipher.wrap(contentEncryptionKeySpec);
    } catch (GeneralSecurityException e) {
      throw new CMSException("cannot process content encryption key: " + e.getMessage(), e);
    }
  }
}