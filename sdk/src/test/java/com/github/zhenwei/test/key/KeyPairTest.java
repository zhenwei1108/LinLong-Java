package com.github.zhenwei.test.key;

import com.github.zhenwei.core.util.encoders.Hex;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.builder.KeyBuilder;
import com.github.zhenwei.sdk.builder.SignBuilder;
import com.github.zhenwei.sdk.enums.KeyEnum;
import com.github.zhenwei.sdk.enums.KeyPairAlgEnum;
import com.github.zhenwei.sdk.enums.SignAlgEnum;
import com.github.zhenwei.sdk.exception.BaseWeGooException;
import com.github.zhenwei.sdk.util.Base64Util;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.IdentityHashMap;
import java.util.Map;
import org.junit.Test;

public class KeyPairTest {

  @Test
  public void genRsa1024Key() throws BaseWeGooException {
    KeyBuilder builder = new KeyBuilder(new WeGooProvider());
    KeyPair keyPair = builder.buildKeyPair(KeyPairAlgEnum.RSA_1024);
    System.out.println(Base64Util.encode(keyPair.getPrivate().getEncoded()));
    System.out.println(Base64Util.encode(keyPair.getPublic().getEncoded()));

    BCRSAPublicKey aPublic = (BCRSAPublicKey) keyPair.getPublic();
    //大素数
    System.out.println("modulus:" + aPublic.getModulus().toString());
    BigInteger mod = aPublic.getModulus().mod(BigInteger.valueOf(128));
    System.out.println(mod);
    //指数
    System.out.println("exponent:" + aPublic.getPublicExponent().intValue());
  }

  @Test
  public void genSM2Key() throws BaseWeGooException {
    KeyBuilder builder = new KeyBuilder(new WeGooProvider());
    KeyPair keyPair = builder.buildKeyPair(KeyPairAlgEnum.SM2_256);
    System.out.println(Base64Util.encode(keyPair.getPrivate().getEncoded()));
    System.out.println(Base64Util.encode(keyPair.getPublic().getEncoded()));
    SignBuilder signBuilder = new SignBuilder(new WeGooProvider());
    byte[] signatureSourceData = signBuilder.signatureSourceData(SignAlgEnum.SM3_WITH_SM2,
        keyPair.getPrivate(), "sadfadf".getBytes(StandardCharsets.UTF_8));
    System.out.println(Base64Util.encode(signatureSourceData));

  }

  @Test
  public void genSm4Key() throws BaseWeGooException {
    WeGooProvider weGooProvider = new WeGooProvider();
    Key key = new KeyBuilder(weGooProvider).buildKey(KeyEnum.SM4_128);
    System.out.println(Base64Util.encode(key.getEncoded()));
    System.out.println("key len :" + key.getEncoded().length);
  }

  @Test
  public void covertKeyPair() throws Exception {
    KeyBuilder builder = new KeyBuilder(new WeGooProvider());
    KeyPair keyPair = builder.buildKeyPair(KeyPairAlgEnum.SM2_256);
    System.out.println("公钥:" + Hex.toHexString(keyPair.getPublic().getEncoded()));
    System.out.println("私钥:" + Hex.toHexString(keyPair.getPrivate().getEncoded()));
    PublicKey publicKey = builder.covertPublicKey(keyPair.getPublic().getEncoded());
    PrivateKey privateKey = builder.covertPrivateKey(keyPair.getPrivate().getEncoded());
    System.out.println("公钥:" + Hex.toHexString(publicKey.getEncoded()));
    System.out.println("私钥:" + Hex.toHexString(privateKey.getEncoded()));
  }

  @Test
  public void getRealKey() throws BaseWeGooException {
    KeyBuilder builder = new KeyBuilder(new WeGooProvider());
    KeyPair keyPair = builder.buildKeyPair(KeyPairAlgEnum.SM2_256);
    System.out.println("公钥:" + Hex.toHexString(keyPair.getPublic().getEncoded()));
    System.out.println("私钥:" + Hex.toHexString(keyPair.getPrivate().getEncoded()));
    //获取裸公钥
    byte[] realPublicKey = builder.getRealPublicKey(keyPair.getPublic());
    System.out.println(Hex.toHexString(realPublicKey));
    //获取裸私钥
    byte[] realPrivateKey = builder.getRealPrivateKey(keyPair.getPrivate());
    System.out.println(Hex.toHexString(realPrivateKey));


  }


  public void forceAuth(Provider provider) {
    try {
      Class<?> aClass = Class.forName("javax.crypto.JceSecurity");
      Map<Provider, Object> verificationResults = new IdentityHashMap<>();
      verificationResults.put(provider, true);
      Field field = aClass.getDeclaredField("verificationResults");
      field.setAccessible(true);
      Field modifiers = field.getClass().getDeclaredField("modifiers");
      modifiers.setAccessible(true);
      modifiers.setInt(field, field.getModifiers() & ~Modifier.FINAL);
      field.set(verificationResults, verificationResults);
      Security.addProvider(provider);
    } catch (Exception e) {
      e.printStackTrace();
    }

  }

}