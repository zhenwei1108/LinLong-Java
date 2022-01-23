package com.github.zhenwei.core.crypto.util;


import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.DERNull;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.kisa.KISAObjectIdentifiers;
import com.github.zhenwei.core.asn1.misc.CAST5CBCParameters;
import com.github.zhenwei.core.asn1.nist.NISTObjectIdentifiers;
import com.github.zhenwei.core.asn1.ntt.NTTObjectIdentifiers;
import com.github.zhenwei.core.asn1.oiw.OIWObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.RC2CBCParameter;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import java.security.SecureRandom;


/**
 * Factory methods for common AlgorithmIdentifiers.
 */
public class AlgorithmIdentifierFactory {

  private AlgorithmIdentifierFactory() {

  }

  static final ASN1ObjectIdentifier IDEA_CBC = new ASN1ObjectIdentifier(
      "1.3.6.1.4.1.188.7.1.1.2").intern();
  static final ASN1ObjectIdentifier CAST5_CBC = new ASN1ObjectIdentifier(
      "1.2.840.113533.7.66.10").intern();

  private static final short[] rc2Table = {
      0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a, 0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd,
      0xd0,
      0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b, 0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21,
      0x5a,
      0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda, 0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80,
      0x36,
      0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8, 0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8,
      0x0c,
      0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17, 0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8,
      0x60,
      0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72, 0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84,
      0xfa,
      0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd, 0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06,
      0x4e,
      0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b, 0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4,
      0xbf,
      0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77, 0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62,
      0xc6,
      0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3, 0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61,
      0xe3,
      0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e, 0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d,
      0x6c,
      0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d, 0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01,
      0xe2,
      0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46, 0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40,
      0xb5,
      0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97, 0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d,
      0xa5,
      0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef, 0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c,
      0x2f,
      0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf, 0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab
  };

  /**
   * Create an AlgorithmIdentifier for the passed in encryption algorithm.
   *
   * @param encryptionOID OID for the encryption algorithm
   * @param keySize       key size in bits (-1 if unknown)
   * @param random        SecureRandom to use for parameter generation.
   * @return a full AlgorithmIdentifier including parameters
   * @throws IllegalArgumentException if encryptionOID cannot be matched
   */
  public static AlgorithmIdentifier generateEncryptionAlgID(ASN1ObjectIdentifier encryptionOID,
      int keySize, SecureRandom random)
      throws IllegalArgumentException {
    if (encryptionOID.equals(NISTObjectIdentifiers.id_aes128_CBC)
        || encryptionOID.equals(NISTObjectIdentifiers.id_aes192_CBC)
        || encryptionOID.equals(NISTObjectIdentifiers.id_aes256_CBC)
        || encryptionOID.equals(NTTObjectIdentifiers.id_camellia128_cbc)
        || encryptionOID.equals(NTTObjectIdentifiers.id_camellia192_cbc)
        || encryptionOID.equals(NTTObjectIdentifiers.id_camellia256_cbc)
        || encryptionOID.equals(KISAObjectIdentifiers.id_seedCBC)) {
      byte[] iv = new byte[16];

      random.nextBytes(iv);

      return new AlgorithmIdentifier(encryptionOID, new DEROctetString(iv));
    } else if (encryptionOID.equals(NISTObjectIdentifiers.id_aes128_GCM)
        || encryptionOID.equals(NISTObjectIdentifiers.id_aes192_GCM)
        || encryptionOID.equals(NISTObjectIdentifiers.id_aes256_GCM)) {
      byte[] iv = new byte[12];

      random.nextBytes(iv);

      return new AlgorithmIdentifier(encryptionOID, new GCMParameters(iv, 16));
    } else if (encryptionOID.equals(NISTObjectIdentifiers.id_aes128_CCM)
        || encryptionOID.equals(NISTObjectIdentifiers.id_aes192_CCM)
        || encryptionOID.equals(NISTObjectIdentifiers.id_aes256_CCM)) {
      byte[] iv = new byte[8];

      random.nextBytes(iv);

      return new AlgorithmIdentifier(encryptionOID, new CCMParameters(iv, 16));
    } else if (encryptionOID.equals(PKCSObjectIdentifiers.des_EDE3_CBC)
        || encryptionOID.equals(IDEA_CBC)
        || encryptionOID.equals(OIWObjectIdentifiers.desCBC)) {
      byte[] iv = new byte[8];

      random.nextBytes(iv);

      return new AlgorithmIdentifier(encryptionOID, new DEROctetString(iv));
    } else if (encryptionOID.equals(CAST5_CBC)) {
      byte[] iv = new byte[8];

      random.nextBytes(iv);

      CAST5CBCParameters cbcParams = new CAST5CBCParameters(iv, keySize);

      return new AlgorithmIdentifier(encryptionOID, cbcParams);
    } else if (encryptionOID.equals(PKCSObjectIdentifiers.rc4)) {
      return new AlgorithmIdentifier(encryptionOID, DERNull.INSTANCE);
    } else if (encryptionOID.equals(PKCSObjectIdentifiers.RC2_CBC)) {
      byte[] iv = new byte[8];

      random.nextBytes(iv);

      RC2CBCParameter cbcParams = new RC2CBCParameter(rc2Table[128], iv);

      return new AlgorithmIdentifier(encryptionOID, cbcParams);
    } else {
      throw new IllegalArgumentException("unable to match algorithm");
    }
  }
}