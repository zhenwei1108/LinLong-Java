package com.github.zhenwei.test.key;

import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.enums.KeyAlgEnum;
import com.github.zhenwei.sdk.exception.BaseWeGooException;
import com.github.zhenwei.sdk.key.KeyBuilder;
import com.github.zhenwei.sdk.util.Base64Util;
import java.security.KeyPair;
import org.junit.Test;

public class KeyPairTest {

  @Test
  public void genRsa1024Key() throws BaseWeGooException {
    KeyBuilder builder = new KeyBuilder(new WeGooProvider());
    KeyPair keyPair = builder.build(KeyAlgEnum.RSA_1024);
    System.out.println(Base64Util.encode(keyPair.getPrivate().getEncoded()));
    System.out.println(Base64Util.encode(keyPair.getPublic().getEncoded()));
  }



  @Test
  public void genSM2Key() throws BaseWeGooException {
    KeyBuilder builder = new KeyBuilder(new WeGooProvider());
    KeyPair keyPair = builder.build(KeyAlgEnum.SM2_256);
    System.out.println(Base64Util.encode(keyPair.getPrivate().getEncoded()));
    System.out.println(Base64Util.encode(keyPair.getPublic().getEncoded()));
  }

}