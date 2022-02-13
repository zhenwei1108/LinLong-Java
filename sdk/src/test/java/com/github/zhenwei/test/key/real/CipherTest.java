package com.github.zhenwei.test.key.real;

import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.builder.CipherBuilder;
import com.github.zhenwei.sdk.builder.KeyBuilder;
import com.github.zhenwei.sdk.enums.CipherAlgEnum;
import com.github.zhenwei.sdk.enums.KeyPairAlgEnum;
import com.github.zhenwei.sdk.exception.BaseWeGooException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import org.junit.Test;

public class CipherTest {

  @Test
  public void encDecDataTest() throws BaseWeGooException {
    WeGooProvider provider = new WeGooProvider();
    CipherBuilder builder = new CipherBuilder(provider);
    KeyBuilder keyBuilder = new KeyBuilder(provider);
    KeyPair keyPair = keyBuilder.buildKeyPair(KeyPairAlgEnum.SM2_256);
    byte[] data = "this is my encrypt data test".getBytes(StandardCharsets.UTF_8);
    byte[] encryptedData = builder.cipher(CipherAlgEnum.SM2, keyPair.getPublic(), data, true);
    data = builder.cipher(CipherAlgEnum.SM2, keyPair.getPrivate(), encryptedData, false);
    System.out.println("解密结果: " + new String(data));


  }


}