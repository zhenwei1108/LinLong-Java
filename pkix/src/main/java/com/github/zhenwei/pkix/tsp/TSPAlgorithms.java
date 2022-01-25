package com.github.zhenwei.pkix.tsp;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.core.asn1.nist.NISTObjectIdentifiers;
import com.github.zhenwei.core.asn1.oiw.OIWObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.rosstandart.RosstandartObjectIdentifiers;
import com.github.zhenwei.core.asn1.teletrust.TeleTrusTObjectIdentifiers;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Recognised hash algorithms for the time stamp protocol.
 */
public interface TSPAlgorithms {

  public static final ASN1ObjectIdentifier MD5 = PKCSObjectIdentifiers.md5;

  public static final ASN1ObjectIdentifier SHA1 = OIWObjectIdentifiers.idSHA1;

  public static final ASN1ObjectIdentifier SHA224 = NISTObjectIdentifiers.id_sha224;
  public static final ASN1ObjectIdentifier SHA256 = NISTObjectIdentifiers.id_sha256;
  public static final ASN1ObjectIdentifier SHA384 = NISTObjectIdentifiers.id_sha384;
  public static final ASN1ObjectIdentifier SHA512 = NISTObjectIdentifiers.id_sha512;

  public static final ASN1ObjectIdentifier RIPEMD128 = TeleTrusTObjectIdentifiers.ripemd128;
  public static final ASN1ObjectIdentifier RIPEMD160 = TeleTrusTObjectIdentifiers.ripemd160;
  public static final ASN1ObjectIdentifier RIPEMD256 = TeleTrusTObjectIdentifiers.ripemd256;

  public static final ASN1ObjectIdentifier GOST3411 = CryptoProObjectIdentifiers.gostR3411;

  public static final ASN1ObjectIdentifier GOST3411_2012_256 = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;

  public static final ASN1ObjectIdentifier GOST3411_2012_512 = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512;

  public static final ASN1ObjectIdentifier SM3 = GMObjectIdentifiers.sm3;

  public static final Set ALLOWED = new HashSet(Arrays.asList(
      new ASN1ObjectIdentifier[]{SM3, GOST3411, GOST3411_2012_256, GOST3411_2012_512, MD5, SHA1,
          SHA224, SHA256, SHA384, SHA512, RIPEMD128, RIPEMD160, RIPEMD256}));
}