package com.github.zhenwei.core.pqc.crypto.lms;


import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.nist.NISTObjectIdentifiers;
import java.util.HashMap;
import java.util.Map;


public class LMSigParameters {

  public static final org.bouncycastle.pqc.crypto.lms.LMSigParameters lms_sha256_n32_h5 = new org.bouncycastle.pqc.crypto.lms.LMSigParameters(
      5, 32, 5, NISTObjectIdentifiers.id_sha256);
  public static final org.bouncycastle.pqc.crypto.lms.LMSigParameters lms_sha256_n32_h10 = new org.bouncycastle.pqc.crypto.lms.LMSigParameters(
      6, 32, 10, NISTObjectIdentifiers.id_sha256);
  public static final org.bouncycastle.pqc.crypto.lms.LMSigParameters lms_sha256_n32_h15 = new org.bouncycastle.pqc.crypto.lms.LMSigParameters(
      7, 32, 15, NISTObjectIdentifiers.id_sha256);
  public static final org.bouncycastle.pqc.crypto.lms.LMSigParameters lms_sha256_n32_h20 = new org.bouncycastle.pqc.crypto.lms.LMSigParameters(
      8, 32, 20, NISTObjectIdentifiers.id_sha256);
  public static final org.bouncycastle.pqc.crypto.lms.LMSigParameters lms_sha256_n32_h25 = new org.bouncycastle.pqc.crypto.lms.LMSigParameters(
      9, 32, 25, NISTObjectIdentifiers.id_sha256);

  private static Map<Object, org.bouncycastle.pqc.crypto.lms.LMSigParameters> paramBuilders = new HashMap<Object, org.bouncycastle.pqc.crypto.lms.LMSigParameters>() {
    {
      put(lms_sha256_n32_h5.type, lms_sha256_n32_h5);
      put(lms_sha256_n32_h10.type, lms_sha256_n32_h10);
      put(lms_sha256_n32_h15.type, lms_sha256_n32_h15);
      put(lms_sha256_n32_h20.type, lms_sha256_n32_h20);
      put(lms_sha256_n32_h25.type, lms_sha256_n32_h25);
    }
  };

  private final int type;
  private final int m;
  private final int h;
  private final ASN1ObjectIdentifier digestOid;

  protected LMSigParameters(int type, int m, int h, ASN1ObjectIdentifier digestOid) {
    this.type = type;
    this.m = m;
    this.h = h;
    this.digestOid = digestOid;
  }

  public int getType() {
    return type;
  }

  public int getH() {
    return h;
  }

  public int getM() {
    return m;
  }

  public ASN1ObjectIdentifier getDigestOID() {
    return digestOid;
  }

  static org.bouncycastle.pqc.crypto.lms.LMSigParameters getParametersForType(int type) {
    return paramBuilders.get(type);
  }
}