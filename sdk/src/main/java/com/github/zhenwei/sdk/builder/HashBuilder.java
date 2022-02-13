package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.crypto.digests.SM3Digest;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.ec.BCECPublicKey;
import com.github.zhenwei.sdk.enums.DigestAlgEnum;
import com.github.zhenwei.sdk.enums.exception.DigestExceptionMessageEnum;
import com.github.zhenwei.sdk.exception.WeGooDigestException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.PublicKey;

/**
 * @description: 摘要算法实现
 * @author: zhangzhenwei
 * @date: 2022/2/9 22:47
 */
public class HashBuilder {

  private Provider provider;

  public HashBuilder(Provider provider) {
    this.provider = provider;
  }

  /**
   * @param [publicKey, source]
   * @return byte[]
   * @author zhangzhenwei
   * @description SM3公钥参与运算
   * @date 2022/2/9 22:48
   */
  private byte[] sm3Digest(DigestParams digestParams, byte[] source) {
    SM3Digest digest = new SM3Digest();
    PublicKey publicKey = digestParams.getPublicKey();
    if (publicKey instanceof BCECPublicKey) {
      BCECPublicKey key = (BCECPublicKey) publicKey;
      digest.init(digestParams.getUserID(), key.getParameters().getCurve(),
          key.getParameters().getG(), key.getQ());
    }
    byte[] hash = new byte[digest.getDigestSize()];
    digest.update(source, 0, source.length);
    digest.doFinal(hash, 0);
    return hash;
  }

  public byte[] digest(DigestAlgEnum digestAlgEnum, byte[] source, DigestParams digestParams)
      throws WeGooDigestException {
    try {
      //SM3算法传入公钥需特殊处理
      if (digestAlgEnum == DigestAlgEnum.SM3 && digestParams != null) {
        return sm3Digest(digestParams, source);
      }
      MessageDigest digest = MessageDigest.getInstance(digestAlgEnum.name(), provider);
      digest.update(source);
      return digest.digest();
    } catch (Exception e) {
      throw new WeGooDigestException(DigestExceptionMessageEnum.digest_data_err, e);
    }
  }

  public byte[] digest(DigestAlgEnum digestAlgEnum, byte[] source) throws WeGooDigestException {
    return digest(digestAlgEnum, source, null);
  }


}