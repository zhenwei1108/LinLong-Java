package com.github.zhenwei.core.asn1.x509;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1GeneralizedTime;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERTaggedObject;
import java.util.Enumeration;

/**
 * <pre>
 *    PrivateKeyUsagePeriod ::= SEQUENCE {
 *      notBefore       [0]     GeneralizedTime OPTIONAL,
 *      notAfter        [1]     GeneralizedTime OPTIONAL }
 * </pre>
 */
public class PrivateKeyUsagePeriod
    extends ASN1Object {

  public static PrivateKeyUsagePeriod getInstance(Object obj) {
    if (obj instanceof PrivateKeyUsagePeriod) {
      return (PrivateKeyUsagePeriod) obj;
    }

    if (obj != null) {
      return new PrivateKeyUsagePeriod(ASN1Sequence.getInstance(obj));
    }

    return null;
  }

  private ASN1GeneralizedTime _notBefore, _notAfter;

  private PrivateKeyUsagePeriod(ASN1Sequence seq) {
    Enumeration en = seq.getObjects();
    while (en.hasMoreElements()) {
      ASN1TaggedObject tObj = (ASN1TaggedObject) en.nextElement();

      if (tObj.getTagNo() == 0) {
        _notBefore = ASN1GeneralizedTime.getInstance(tObj, false);
      } else if (tObj.getTagNo() == 1) {
        _notAfter = ASN1GeneralizedTime.getInstance(tObj, false);
      }
    }
  }

  public ASN1GeneralizedTime getNotBefore() {
    return _notBefore;
  }

  public ASN1GeneralizedTime getNotAfter() {
    return _notAfter;
  }

  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(2);

    if (_notBefore != null) {
      v.add(new DERTaggedObject(false, 0, _notBefore));
    }
    if (_notAfter != null) {
      v.add(new DERTaggedObject(false, 1, _notAfter));
    }

    return new DERSequence(v);
  }
}