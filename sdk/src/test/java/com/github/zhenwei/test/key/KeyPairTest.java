package com.github.zhenwei.test.key;

import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.enums.KeyEnum;
import com.github.zhenwei.sdk.enums.KeyPairEnum;
import com.github.zhenwei.sdk.exception.BaseWeGooException;
import com.github.zhenwei.sdk.key.KeyBuilder;
import com.github.zhenwei.sdk.util.Base64Util;
import java.security.Key;
import java.security.KeyPair;
import org.junit.Test;

public class KeyPairTest {

  @Test
  public void genRsa1024Key() throws BaseWeGooException {
    KeyBuilder builder = new KeyBuilder(new WeGooProvider());
    KeyPair keyPair = builder.buildKeyPair(KeyPairEnum.RSA_1024);
    System.out.println(Base64Util.encode(keyPair.getPrivate().getEncoded()));
    System.out.println(Base64Util.encode(keyPair.getPublic().getEncoded()));
  }



  @Test
  public void genSM2Key() throws BaseWeGooException {
    KeyBuilder builder = new KeyBuilder(new WeGooProvider());
    KeyPair keyPair = builder.buildKeyPair(KeyPairEnum.SM2_256);
    System.out.println(Base64Util.encode(keyPair.getPrivate().getEncoded()));
    System.out.println(Base64Util.encode(keyPair.getPublic().getEncoded()));
  }

  @Test
  public void genSm4Key() throws BaseWeGooException {
    Key key = new KeyBuilder().buildKey(KeyEnum.SM4_128);
    System.out.println(Base64Util.encode(key.getEncoded()));
    System.out.println("key len :"+key.getEncoded().length);
  }

  @Test
  public void test(){
//    URL url = new URL("jar:" + var1.toString() + "!/");
//    JarURLConnection urlConnection = url.openConnection();
//    JarFile jarFile = urlConnection.getJarFile();
//
//    new JarVerifier.JarHolder(jarFile, false);
  }

}