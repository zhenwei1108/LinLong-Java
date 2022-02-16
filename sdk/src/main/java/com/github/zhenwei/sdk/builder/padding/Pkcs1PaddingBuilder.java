package com.github.zhenwei.sdk.builder.padding;

import com.github.zhenwei.core.asn1.ASN1Encoding;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.DERNull;
import com.github.zhenwei.core.asn1.nist.NISTObjectIdentifiers;
import com.github.zhenwei.core.asn1.oiw.OIWObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.DigestInfo;
import com.github.zhenwei.core.crypto.CryptoServicesRegistrar;
import com.github.zhenwei.sdk.enums.DigestAlgEnum;
import com.github.zhenwei.sdk.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.sdk.exception.WeGooCryptoException;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * @description: PKCS1  填充, 去填充. 参考 RFC-2437. EMSA-PKCS1-v1_5-ENCODE
 * @author: zhangzhenwei
 * @date: 2022/2/13 21:57
 */
public class Pkcs1PaddingBuilder {

  /**
   * 若为私钥,标志位01,中间填充FF,保证每次填充一致,签名结果的一致 若为公钥,标志位02,则中间填充使用随机数 00 01/02 || PS(随机数/OxFF) || 00 ||
   * T(数据摘要)
   */
  public static byte[] encodePkcs1Padding(byte[] data, boolean isPrivate, int modulusLength,
      String policyType) throws WeGooCryptoException {
    try {
      if (modulusLength % 1024 == 0) {
        modulusLength = modulusLength / 8;
      }
      if (modulusLength % 128 != 0) {
        throw new WeGooCryptoException(CryptoExceptionMassageEnum.params_err);
      }
      ASN1ObjectIdentifier hashOid = null;
      if (DigestAlgEnum.SHA256.equals(policyType)) {
        hashOid = NISTObjectIdentifiers.id_sha256;
      } else if (DigestAlgEnum.SHA1.equals(policyType)) {
        hashOid = OIWObjectIdentifiers.idSHA1;
      } else if (DigestAlgEnum.SHA224.equals(policyType)) {
        hashOid = NISTObjectIdentifiers.id_sha224;
      } else if (DigestAlgEnum.SHA384.equals(policyType)) {
        hashOid = NISTObjectIdentifiers.id_sha384;
      } else if (DigestAlgEnum.SHA512.equals(policyType)) {
        hashOid = NISTObjectIdentifiers.id_sha512;
      }

      //组装摘要值
      MessageDigest digest = MessageDigest.getInstance(policyType);
      digest.update(data);
      byte[] hash = digest.digest();
      int T = hash.length;
      int emLen = modulusLength - 1;
      if (emLen < (T + 10)) {
        /*intended encoded message length too short*/
        throw new WeGooCryptoException(CryptoExceptionMassageEnum.params_short_err);
      }
      int psLength = Math.max(emLen - T - 2, 8);
      AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(hashOid, DERNull.INSTANCE);
      DigestInfo dInfo = new DigestInfo(algorithmIdentifier, hash);
      byte[] in = dInfo.getEncoded(ASN1Encoding.DER);
      SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

      byte[] block = new byte[3 + psLength + T];
      int i;
      int inLen = in.length;
      if (isPrivate) {
        block[1] = 1;

        for (i = 2; i != block.length - inLen; ++i) {
          block[i] = -1;
        }
      } else {
        random.nextBytes(block);
        block[0] = 0;
        block[1] = 2;

        for (i = 2; i != block.length - inLen; ++i) {
          while (block[i] == 0) {
            block[i] = (byte) random.nextInt();
          }
        }
      }
      block[block.length - inLen - 1] = 0;
      System.arraycopy(in, 0, block, block.length - inLen, inLen);
      return block;
    } catch (Exception e) {
      throw new WeGooCryptoException(e);
    }
  }

}