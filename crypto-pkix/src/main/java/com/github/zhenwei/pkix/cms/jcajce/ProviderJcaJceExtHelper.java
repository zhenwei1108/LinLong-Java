package com.github.zhenwei.pkix.cms.jcajce;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.operator.SymmetricKeyUnwrapper;
import com.github.zhenwei.pkix.operator.jcajce.JceAsymmetricKeyUnwrapper;
import com.github.zhenwei.pkix.operator.jcajce.JceKTSKeyUnwrapper;
import com.github.zhenwei.pkix.operator.jcajce.JceSymmetricKeyUnwrapper;
import com.github.zhenwei.provider.jcajce.util.ProviderJcaJceHelper;
import java.security.PrivateKey;
import java.security.Provider;
import javax.crypto.SecretKey;

class ProviderJcaJceExtHelper
    extends ProviderJcaJceHelper
    implements JcaJceExtHelper {

  public ProviderJcaJceExtHelper(Provider provider) {
    super(provider);
  }

  public JceAsymmetricKeyUnwrapper createAsymmetricUnwrapper(
      AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey) {
    keyEncryptionKey = CMSUtils.cleanPrivateKey(keyEncryptionKey);
    return new JceAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey).setProvider(
        provider);
  }

  public JceKTSKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm,
      PrivateKey keyEncryptionKey, byte[] partyUInfo, byte[] partyVInfo) {
    keyEncryptionKey = CMSUtils.cleanPrivateKey(keyEncryptionKey);
    return new JceKTSKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey, partyUInfo,
        partyVInfo).setProvider(provider);
  }

  public SymmetricKeyUnwrapper createSymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm,
      SecretKey keyEncryptionKey) {
    return new JceSymmetricKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey).setProvider(
        provider);
  }
}