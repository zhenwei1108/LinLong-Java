package com.github.zhenwei.sdk.enums;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.sdk.exception.WeGooCryptoException;
import java.util.Arrays;

/**
 * @description: 签名算法
 * @author: zhangzhenwei
 * @date: 2022/2/3 20:57
 */
public enum SignAlgEnum implements BaseAlgEnum {
  SM3_WITH_SM2("SM3WITHSM2", GMObjectIdentifiers.sm2sign_with_sm3),
  SHA1_WITH_RSA("SHA1WITHRSA", PKCSObjectIdentifiers.sha1WithRSAEncryption),
  SHA224_WITH_RSA("SHA224WITHRSA", PKCSObjectIdentifiers.sha224WithRSAEncryption),
  SHA256_WITH_RSA("SHA256WITHRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption),
  SHA384_WITH_RSA("SHA384WITHRSA", PKCSObjectIdentifiers.sha384WithRSAEncryption),
  SHA512_WITH_RSA("SHA512WITHRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption),

  ;

  private String alg;
  private ASN1ObjectIdentifier oid;

  SignAlgEnum(String alg, ASN1ObjectIdentifier oid) {
    this.alg = alg;
    this.oid = oid;
  }

  public String getAlg() {
    return alg;
  }

  public ASN1ObjectIdentifier getOid() {
    return oid;
  }

  public static SignAlgEnum match(ASN1ObjectIdentifier oid) throws WeGooCryptoException {
    return Arrays.stream(values()).filter(value -> value.getOid().getId().equals(oid.getId())).findFirst()
        .orElseThrow(() -> new WeGooCryptoException("not match SignAlgEnum of:" + oid.getId()));
  }


}