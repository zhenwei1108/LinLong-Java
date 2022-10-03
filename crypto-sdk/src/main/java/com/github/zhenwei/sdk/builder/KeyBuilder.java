package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DLSequence;
import com.github.zhenwei.core.asn1.gm.GMNamedCurves;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.core.enums.KeyEnum;
import com.github.zhenwei.core.enums.KeyPairAlgEnum;
import com.github.zhenwei.core.enums.exception.IExceptionEnum;
import com.github.zhenwei.core.enums.exception.KeyExceptionMessageEnum;
import com.github.zhenwei.core.exception.BaseWeGooException;
import com.github.zhenwei.core.exception.WeGooCryptoException;
import com.github.zhenwei.core.exception.WeGooKeyException;
import com.github.zhenwei.sdk.init.ProviderEngine;
import lombok.val;
import lombok.var;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @description: 密钥构造者
 * @author: zhangzhenwei
 * @date: 2022/2/11 23:33
 */
public final class KeyBuilder {


  /**
   * @param [keyPairEnum]
   * @return java.security.KeyPair
   * @author zhangzhenwei
   * @description 生成非对称密钥对
   * @date 2022/2/11 22:35
   * @since 1.0
   */
  public static KeyPair buildKeyPair(KeyPairAlgEnum keyPairEnum) throws WeGooKeyException {
    try {
      var generator = KeyPairGenerator.getInstance(keyPairEnum.getAlg(), ProviderEngine.getProvider());
      if (keyPairEnum == KeyPairAlgEnum.SM2_256) {
        //SM2 算法曲线
        var name = GMNamedCurves.getName(GMObjectIdentifiers.sm2p256v1);
        var sm2Spec = new ECGenParameterSpec(name);
        generator.initialize(sm2Spec, new SecureRandom());
      } else {
        generator.initialize(keyPairEnum.getKeyLen());
      }
      return generator.generateKeyPair();
    } catch (Exception e) {
      throw new WeGooKeyException(KeyExceptionMessageEnum.generate_keypair_err, e);
    }
  }

  /**
   * @param [keyEnum]
   * @return java.security.Key
   * @author zhangzhenwei
   * @description 生成对称密钥
   * @date 2022/2/11 22:34
   * @since 1.0
   */
  public static Key buildKey(KeyEnum keyEnum) throws BaseWeGooException {
    try {
      val generator = KeyGenerator.getInstance(keyEnum.getAlg(), ProviderEngine.getProvider());
      generator.init(keyEnum.getKeyLen(), new SecureRandom());
      return generator.generateKey();
    } catch (Exception e) {
      throw new WeGooKeyException(KeyExceptionMessageEnum.generate_key_err, e);
    }
  }

  /**
   * @param [publicKey]
   * @return java.security.PublicKey
   * @author zhangzhenwei
   * @description 公钥转换  byte[] to {@link PublicKey}
   * @date 2022/2/11 22:34
   * @since 1.0
   */
  public static PublicKey convertPublicKey(byte[] publicKey) throws WeGooKeyException {
    try {
      SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(publicKey);
      if (keyInfo == null) {
        throw new WeGooKeyException(IExceptionEnum.params_err);
      }
      X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey);
      KeyFactory factory = KeyFactory.getInstance(keyInfo.getAlgorithm().getAlgorithm().toString(),
          new WeGooProvider());
      return factory.generatePublic(spec);
    } catch (WeGooCryptoException e) {
      throw e;
    } catch (Exception e) {
      throw new WeGooKeyException(KeyExceptionMessageEnum.structure_public_key_err, e);
    }
  }

  /**
   * @param [privateKey]
   * @return java.security.PrivateKey
   * @author zhangzhenwei
   * @description 私钥转换  byte[]  to  {@link PrivateKey}
   * @date 2022/2/11 22:34
   * @since 1.0
   */
  public static PrivateKey convertPrivateKey(byte[] privateKey) throws Exception {
    try {
      PrivateKeyInfo info = PrivateKeyInfo.getInstance(privateKey);
      if (info == null) {
        throw new WeGooKeyException(IExceptionEnum.params_err);
      }
      KeyPairAlgEnum algEnum = KeyPairAlgEnum.match(info.getPrivateKeyAlgorithm().getAlgorithm());
      PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey);
      KeyFactory factory = KeyFactory.getInstance(algEnum.getAlg(), new WeGooProvider());
      return factory.generatePrivate(spec);
    } catch (WeGooCryptoException e) {
      throw e;
    } catch (Exception e) {
      throw new WeGooKeyException(KeyExceptionMessageEnum.structure_private_key_err, e);
    }
  }

  /**
   * @param [publicKey]
   * @return byte[]
   * @author zhangzhenwei
   * @description 获取裸公钥
   * @date 2022/2/11 22:33
   * @since 1.0
   */
  public static byte[] getRealPublicKey(PublicKey publicKey) throws WeGooKeyException {
    return getRealPublicKey(publicKey.getEncoded());
  }


  public static byte[] getRealPublicKey(byte[] publicKey) throws WeGooKeyException {
    SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(publicKey);
    if (keyInfo == null) {
      throw new WeGooKeyException(IExceptionEnum.params_err);
    }
    return keyInfo.getPublicKeyData().getOctets();
  }


  /**
   * @param [privateKey]
   * @return byte[]
   * @author zhangzhenwei
   * @description 获取裸私钥
   * @date 2022/2/11 23:06
   * @since 1.0
   */
  public static byte[] getRealPrivateKey(byte[] privateKey) throws WeGooCryptoException {
    try {
      PrivateKeyInfo info = PrivateKeyInfo.getInstance(privateKey);
      if (info == null) {
        throw new WeGooKeyException(IExceptionEnum.params_err);
      }
      KeyPairAlgEnum algEnum = KeyPairAlgEnum.match(info.getPrivateKeyAlgorithm().getAlgorithm());
      //SM2 算法
      if (algEnum.getAlg().equals(KeyPairAlgEnum.SM2_256.getAlg())) {
        DLSequence dlSequence = (DLSequence) DLSequence.fromByteArray(privateKey);
        byte[] priKeys = ((DEROctetString) dlSequence.getObjectAt(2)).getOctets();
        dlSequence = (DLSequence) DLSequence.fromByteArray(priKeys);
        DEROctetString derPriKey = (DEROctetString) dlSequence.getObjectAt(1);
        return derPriKey.getOctets();
      } else {
        return info.getPrivateKey().getOctets();
      }
    } catch (WeGooKeyException e) {
      throw e;
    } catch (Exception e) {
      throw new WeGooKeyException(KeyExceptionMessageEnum.parse_private_key_err, e);
    }

  }

  public static byte[] getRealPrivateKey(PrivateKey privateKey) throws WeGooCryptoException {
    return getRealPrivateKey(privateKey.getEncoded());
  }

  public static Key convertKey(byte[] key, KeyEnum keyEnum) {
    return new SecretKeySpec(key, keyEnum.getAlg());
  }

}