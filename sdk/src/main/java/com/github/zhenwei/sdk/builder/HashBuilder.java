package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.crypto.digests.SM3Digest;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.ec.BCECPublicKey;
import com.github.zhenwei.sdk.enums.DigestAlgEnum;
import com.github.zhenwei.sdk.enums.exception.DigestExceptionMessageEnum;
import com.github.zhenwei.sdk.exception.WeGooDigestException;
import java.security.MessageDigest;
import java.security.PublicKey;

/**
 * @description: 摘要算法实现
 * @author: zhangzhenwei
 * @date: 2022/2/9 22:47
 */
public class HashBuilder {

  /**
   * @param [publicKey, source]
   * @return byte[]
   * @author zhangzhenwei
   * @description todo 后续考虑合并接口, 使用统一入参, 如构建 param
   * @date 2022/2/9 22:48
   */
  public static byte[] sm3Digest(PublicKey publicKey, byte[] source) {
    SM3Digest digest = new SM3Digest();

    if (publicKey instanceof BCECPublicKey) {
      BCECPublicKey key = (BCECPublicKey) publicKey;
      digest.init(key.getParameters().getCurve(), key.getParameters().getG(), key.getQ());
    }
    byte[] hash = new byte[digest.getDigestSize()];
    digest.update(source, 0, source.length);
    digest.doFinal(hash, 0);
    return hash;
  }

  public byte[] digest(DigestAlgEnum digestAlgEnum, byte[] source) throws WeGooDigestException {
    try {
      MessageDigest digest = MessageDigest.getInstance(digestAlgEnum.name());
      digest.update(source);
      return digest.digest();
    } catch (Exception e) {
      throw new WeGooDigestException(DigestExceptionMessageEnum.digest_data_err, e);
    }

  }


}