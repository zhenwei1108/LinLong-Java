package com.github.zhenwei.core.enums;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.core.asn1.nist.NISTObjectIdentifiers;
import com.github.zhenwei.core.asn1.oiw.OIWObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.exception.WeGooDigestException;

import java.util.Arrays;

/**
 * @description: 摘要算法 枚举
 * @author: zhangzhenwei
 * @date: 2022/2/9 22:35
 */
public enum DigestAlgEnum implements BaseEnum {
  SM3(32, GMObjectIdentifiers.sm3),
  MD5(16, PKCSObjectIdentifiers.md5),
  SHA1(20, OIWObjectIdentifiers.idSHA1),
  SHA224(28, NISTObjectIdentifiers.id_sha224),
  SHA256(32, NISTObjectIdentifiers.id_sha256),
  SHA384(48, NISTObjectIdentifiers.id_sha384),
  SHA512(64, NISTObjectIdentifiers.id_sha512);

  private int digestLength;
  private ASN1ObjectIdentifier oid;

  DigestAlgEnum(int digestLength, ASN1ObjectIdentifier oid) {
    this.digestLength = digestLength;
    this.oid = oid;
  }

  public int getDigestLength() {
    return digestLength;
  }

  public ASN1ObjectIdentifier getOid() {
    return oid;
  }

  public static DigestAlgEnum match(String name) throws WeGooDigestException {
    return Arrays.stream(values()).filter(digest -> digest.name().equalsIgnoreCase(name))
        .findFirst()
        .orElseThrow(() -> new WeGooDigestException("not match digest alg of: " + name));

  }


}