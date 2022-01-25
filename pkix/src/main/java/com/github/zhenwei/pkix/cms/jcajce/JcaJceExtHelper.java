package com.github.zhenwei.pkix.cms.jcajce;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.operator.SymmetricKeyUnwrapper;
import com.github.zhenwei.pkix.operator.jcajce.JceAsymmetricKeyUnwrapper;
import com.github.zhenwei.pkix.operator.jcajce.JceKTSKeyUnwrapper;
import com.github.zhenwei.provider.jcajce.util.JcaJceHelper;
import java.security.PrivateKey;
import javax.crypto.SecretKey;

interface JcaJceExtHelper
    extends JcaJceHelper {

  JceAsymmetricKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm,
      PrivateKey keyEncryptionKey);

  JceKTSKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm,
      PrivateKey keyEncryptionKey, byte[] partyUInfo, byte[] partyVInfo);

  SymmetricKeyUnwrapper createSymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm,
      SecretKey keyEncryptionKey);
}