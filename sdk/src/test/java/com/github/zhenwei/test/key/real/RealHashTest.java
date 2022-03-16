package com.github.zhenwei.test.key.real;

import com.github.zhenwei.core.util.encoders.Hex;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.builder.params.DigestParams;
import com.github.zhenwei.sdk.builder.HashBuilder;
import com.github.zhenwei.sdk.builder.KeyBuilder;
import com.github.zhenwei.core.enums.DigestAlgEnum;
import com.github.zhenwei.core.enums.KeyPairAlgEnum;
import com.github.zhenwei.core.exception.BaseWeGooException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import org.junit.Test;

public class RealHashTest {


  @Test
  public void sm3Digest() throws BaseWeGooException {
    WeGooProvider provider = new WeGooProvider();
    HashBuilder builder = new HashBuilder(provider);
    byte[] source = "asdf".getBytes(StandardCharsets.UTF_8);
    byte[] digest = builder.digest(DigestAlgEnum.SM3, source);
    System.out.println(Hex.toHexString(digest));

    //公钥参与运算
    KeyBuilder keyBuilder = new KeyBuilder(provider);
    KeyPair keyPair = keyBuilder.buildKeyPair(KeyPairAlgEnum.SM2_256);
    DigestParams digestParams = new DigestParams(keyPair.getPublic());
    digest = builder.digest(DigestAlgEnum.SM3, source, digestParams);
    System.out.println(Hex.toHexString(digest));
  }

}