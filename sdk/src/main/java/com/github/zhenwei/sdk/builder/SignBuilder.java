package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.sdk.enums.SignAlgEnum;
import com.github.zhenwei.sdk.enums.exception.SignatureExceptionMessageEnum;
import com.github.zhenwei.sdk.exception.WeGooSignerException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;

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
      Signature signature = Signature.getInstance(signAlgEnum.getAlg(), provider);
      signature.initSign(privateKey);
      signature.update(source);
      return signature.sign();
    } catch (Exception e) {
      throw new WeGooSignerException(SignatureExceptionMessageEnum.sign_data_err, e);
    }
  }


  /**
   * @param [signedData, ssirce, publicKey]
   * @return boolean
   * @author zhangzhenwei
   * @description 原文验签.  签名值, 原文, 公钥
   * @date 2022/2/6 22:15
   */
  public boolean verifySourceData(SignAlgEnum signAlgEnum, byte[] signedData, byte[] source,
      PublicKey publicKey) throws WeGooSignerException {
    try {
      Signature signature = Signature.getInstance(signAlgEnum.getAlg(), provider);
      signature.initVerify(publicKey);
      signature.update(source);
      return signature.verify(signedData);
    } catch (Exception e) {
      throw new WeGooSignerException(SignatureExceptionMessageEnum.verify_data_err, e);
    }
  }


}