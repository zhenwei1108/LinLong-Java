package com.github.zhenwei.sdk.enums;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.x9.X9ObjectIdentifiers;
import com.github.zhenwei.sdk.exception.WeGooCryptoException;
import java.util.Arrays;

/**
 * @description: 非对称算法, 模长
 * @author: zhangzhenwei
 * @date: 2022/1/25 22:57
 */
public enum KeyPairAlgEnum implements BaseKeyEnum {
  /**
   * asymmetrical key
   * EC 曲线标识符: X9ObjectIdentifiers.id_ecPublicKey
   * SM2算法标识符 {@link com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers#sm2p256v1}
   */
  SM2_256("EC", 256, X9ObjectIdentifiers.id_ecPublicKey),
  RSA_1024("RSA", 1024, PKCSObjectIdentifiers.rsaEncryption),
  RSA_2048("RSA", 2048, PKCSObjectIdentifiers.rsaEncryption),

  ;


  private String alg;

  private int keyLen;

  private ASN1ObjectIdentifier oid;


  KeyPairAlgEnum(String alg, int keyLen, ASN1ObjectIdentifier oid) {
    this.alg = alg;
    this.keyLen = keyLen;
    this.oid = oid;
  }

  KeyPairAlgEnum(String alg, int keyLen) {
    this.alg = alg;
    this.keyLen = keyLen;
  }

  public ASN1ObjectIdentifier getOid() {
    return oid;
  }

  @Override
  public String getAlg() {
    return alg;
  }

  @Override
  public int getKeyLen() {
    return keyLen;
  }

  public static KeyPairAlgEnum match(ASN1ObjectIdentifier identifier) throws WeGooCryptoException {

    return Arrays.stream(values()).filter(oid -> oid.getOid().getId().equals(identifier.getId()))
        .findFirst().orElseThrow(
            () -> new WeGooCryptoException("not match ASN1ObjectIdentifier of:" + identifier.getId()));
  }

}