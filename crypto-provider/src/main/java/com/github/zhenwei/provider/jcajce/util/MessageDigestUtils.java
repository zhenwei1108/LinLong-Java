package com.github.zhenwei.provider.jcajce.util;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.core.asn1.gnu.GNUObjectIdentifiers;
import com.github.zhenwei.core.asn1.iso.ISOIECObjectIdentifiers;
import com.github.zhenwei.core.asn1.nist.NISTObjectIdentifiers;
import com.github.zhenwei.core.asn1.oiw.OIWObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.teletrust.TeleTrusTObjectIdentifiers;
import java.util.HashMap;
import java.util.Map;

public class MessageDigestUtils {

  private static Map<ASN1ObjectIdentifier, String> digestOidMap = new HashMap<ASN1ObjectIdentifier, String>();

  static {
    digestOidMap.put(PKCSObjectIdentifiers.md2, "MD2");
    digestOidMap.put(PKCSObjectIdentifiers.md4, "MD4");
    digestOidMap.put(PKCSObjectIdentifiers.md5, "MD5");
    digestOidMap.put(OIWObjectIdentifiers.idSHA1, "SHA-1");
    digestOidMap.put(NISTObjectIdentifiers.id_sha224, "SHA-224");
    digestOidMap.put(NISTObjectIdentifiers.id_sha256, "SHA-256");
    digestOidMap.put(NISTObjectIdentifiers.id_sha384, "SHA-384");
    digestOidMap.put(NISTObjectIdentifiers.id_sha512, "SHA-512");
    digestOidMap.put(NISTObjectIdentifiers.id_sha512_224, "SHA-512(224)");
    digestOidMap.put(NISTObjectIdentifiers.id_sha512_256, "SHA-512(256)");
    digestOidMap.put(TeleTrusTObjectIdentifiers.ripemd128, "RIPEMD-128");
    digestOidMap.put(TeleTrusTObjectIdentifiers.ripemd160, "RIPEMD-160");
    digestOidMap.put(TeleTrusTObjectIdentifiers.ripemd256, "RIPEMD-128");
    digestOidMap.put(ISOIECObjectIdentifiers.ripemd128, "RIPEMD-128");
    digestOidMap.put(ISOIECObjectIdentifiers.ripemd160, "RIPEMD-160");
    digestOidMap.put(CryptoProObjectIdentifiers.gostR3411, "GOST3411");
    digestOidMap.put(GNUObjectIdentifiers.Tiger_192, "Tiger");
    digestOidMap.put(ISOIECObjectIdentifiers.whirlpool, "Whirlpool");
    digestOidMap.put(NISTObjectIdentifiers.id_sha3_224, "SHA3-224");
    digestOidMap.put(NISTObjectIdentifiers.id_sha3_256, "SHA3-256");
    digestOidMap.put(NISTObjectIdentifiers.id_sha3_384, "SHA3-384");
    digestOidMap.put(NISTObjectIdentifiers.id_sha3_512, "SHA3-512");
    digestOidMap.put(NISTObjectIdentifiers.id_shake128, "SHAKE128");
    digestOidMap.put(NISTObjectIdentifiers.id_shake256, "SHAKE256");
    digestOidMap.put(GMObjectIdentifiers.sm3, "SM3");
  }

  /**
   * Attempt to find a standard JCA name for the digest represented by the passed in OID.
   *
   * @param digestAlgOID the OID of the digest algorithm of interest.
   * @return a string representing the standard name - the OID as a string if none available.
   */
  public static String getDigestName(ASN1ObjectIdentifier digestAlgOID) {
    String name = (String) digestOidMap.get(digestAlgOID);  // for pre 1.5 JDK
    if (name != null) {
      return name;
    }

    return digestAlgOID.getId();
  }
}