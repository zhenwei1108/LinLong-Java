package com.github.zhenwei.test.key.real;

import com.github.zhenwei.core.enums.CipherAlgEnum;
import com.github.zhenwei.core.enums.KeyPairAlgEnum;
import com.github.zhenwei.core.exception.BaseWeGooException;
import com.github.zhenwei.sdk.builder.CipherBuilder;
import com.github.zhenwei.sdk.builder.KeyBuilder;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import org.junit.Test;

public class CipherTest {

  @Test
  public void encDecDataTest() throws BaseWeGooException {
    KeyBuilder keyBuilder = new KeyBuilder();
    //SM2加解密
    KeyPair keyPair = keyBuilder.buildKeyPair(KeyPairAlgEnum.SM2_256);
    byte[] data = "this is my encrypt data test".getBytes(StandardCharsets.UTF_8);
    byte[] iv = new byte[16];
    byte[] encryptedData = CipherBuilder.cipher(CipherAlgEnum.SM2, keyPair.getPublic(), data, iv, true);
    data = CipherBuilder.cipher(CipherAlgEnum.SM2, keyPair.getPrivate(), encryptedData, iv, false);
    System.out.println("解密结果: " + new String(data));

    //RSA加解密
    keyPair = keyBuilder.buildKeyPair(KeyPairAlgEnum.RSA_2048);
    encryptedData = CipherBuilder.cipher(CipherAlgEnum.RSA, keyPair.getPublic(), data, iv, true);
    data = CipherBuilder.cipher(CipherAlgEnum.RSA, keyPair.getPrivate(), encryptedData, iv, false);
    System.out.println("解密结果: " + new String(data));


  }


  public static void main(String[] args) {
    BigInteger five = BigInteger.valueOf(5);
    BigInteger three = BigInteger.valueOf(3);
    System.out.println(five.mod(three));
    System.out.println(five.modPow(three, three));
  }


}