package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.sdk.enums.SignAlgEnum;
import com.github.zhenwei.sdk.exception.WeGooSignerException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;

public class SignBuilder {

  private Provider provider;

  public SignBuilder(Provider provider) {
    this.provider = provider;
  }

  public byte[] sign(SignAlgEnum signAlgEnum, PrivateKey privateKey, byte[] data)
      throws WeGooSignerException {
    try {
      Signature signature = Signature.getInstance(signAlgEnum.getAlg(), provider);
      signature.initSign(privateKey);
      signature.update(data);
      return signature.sign();
    } catch (Exception e) {
      throw new WeGooSignerException();
    }

  }


}