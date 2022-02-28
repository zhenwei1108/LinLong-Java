package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.sdk.enums.SignAlgEnum;
import com.github.zhenwei.sdk.enums.exception.SignatureExceptionMessageEnum;
import com.github.zhenwei.sdk.exception.WeGooSignerException;
import lombok.var;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;

/**
 * @description: 签名验签
 * @author: zhangzhenwei
 * @since 1.0.0
 * @date: 2022/2/16 22:08
 */
public class SignBuilder {

  private Provider provider;

  public SignBuilder(Provider provider) {
    this.provider = provider;
  }

  /**
   * @param [signAlgEnum, privateKey, source]
   * @return byte[]
   * @author zhangzhenwei
   * @description 原文签名
   * @date 2022/2/6 22:21
   */
  public byte[] signatureSourceData(SignAlgEnum signAlgEnum, PrivateKey privateKey, byte[] source)
      throws WeGooSignerException {
    try {
      var signature = Signature.getInstance(signAlgEnum.getAlg(), provider);
      signature.initSign(privateKey);
      signature.update(source);
      return signature.sign();
    } catch (Exception e) {
      throw new WeGooSignerException(SignatureExceptionMessageEnum.sign_data_err, e);
    }
  }


  /**
   * @param [signature, source]
   * @return byte[]
   * @author zhangzhenwei
   * @description signatureSourceData 使用保护私钥进行签名
   * @since: 1.0.0
   * @date 2022/2/27 9:40 上午
   */
  public byte[] signatureSourceData(Signature signature, byte[] source) throws WeGooSignerException {
    try {
      signature.update(source);
      return signature.sign();
    } catch (Exception e) {
      throw new WeGooSignerException(SignatureExceptionMessageEnum.sign_data_err, e);
    }
  }


  /**
   * @param [signedData, source, publicKey]
   * @return boolean
   * @author zhangzhenwei
   * @description 原文验签.  签名值, 原文, 公钥
   * @date 2022/2/6 22:15
   */
  public boolean verifySourceData(SignAlgEnum signAlgEnum, byte[] signedData, byte[] source,
      PublicKey publicKey) throws WeGooSignerException {
    try {
      var signature = Signature.getInstance(signAlgEnum.getAlg(), provider);
      signature.initVerify(publicKey);
      signature.update(source);
      return signature.verify(signedData);
    } catch (Exception e) {
      throw new WeGooSignerException(SignatureExceptionMessageEnum.verify_data_err, e);
    }
  }


}