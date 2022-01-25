package com.github.zhenwei.pkix.util.asn1.cms;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERSequence;
import java.util.Enumeration;

/**
 * <a href="https://tools.ietf.org/html/rfc5544">RFC 5544</a>
 * Binding Documents with Time-Stamps; TimeStampTokenEvidence object.
 * <pre>
 * TimeStampTokenEvidence ::=
 *    SEQUENCE SIZE(1..MAX) OF TimeStampAndCRL
 * </pre>
 */
public class TimeStampTokenEvidence
    extends ASN1Object {

  private TimeStampAndCRL[] timeStampAndCRLs;

  public TimeStampTokenEvidence(TimeStampAndCRL[] timeStampAndCRLs) {
    this.timeStampAndCRLs = copy(timeStampAndCRLs);
  }

  public TimeStampTokenEvidence(TimeStampAndCRL timeStampAndCRL) {
    this.timeStampAndCRLs = new TimeStampAndCRL[1];

    timeStampAndCRLs[0] = timeStampAndCRL;
  }

  private TimeStampTokenEvidence(ASN1Sequence seq) {
    this.timeStampAndCRLs = new TimeStampAndCRL[seq.size()];

    int count = 0;

    for (Enumeration en = seq.getObjects(); en.hasMoreElements(); ) {
      timeStampAndCRLs[count++] = TimeStampAndCRL.getInstance(en.nextElement());
    }
  }

  public static TimeStampTokenEvidence getInstance(ASN1TaggedObject tagged, boolean explicit) {
    return getInstance(ASN1Sequence.getInstance(tagged, explicit));
  }

  /**
   * Return a TimeStampTokenEvidence object from the given object.
   * <p>
   * Accepted inputs:
   * <ul>
   * <li> null &rarr; null
   * <li> {@link TimeStampTokenEvidence} object
   * <li> {@link com.github.zhenwei.core.asn1.ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with TimeStampTokenEvidence structure inside
   * </ul>
   *
   * @param obj the object we want converted.
   * @throws IllegalArgumentException if the object cannot be converted.
   */
  public static TimeStampTokenEvidence getInstance(Object obj) {
    if (obj instanceof TimeStampTokenEvidence) {
      return (TimeStampTokenEvidence) obj;
    } else if (obj != null) {
      return new TimeStampTokenEvidence(ASN1Sequence.getInstance(obj));
    }

    return null;
  }

  public TimeStampAndCRL[] toTimeStampAndCRLArray() {
    return copy(timeStampAndCRLs);
  }

  private TimeStampAndCRL[] copy(TimeStampAndCRL[] tsAndCrls) {
    TimeStampAndCRL[] tmp = new TimeStampAndCRL[tsAndCrls.length];

    System.arraycopy(tsAndCrls, 0, tmp, 0, tmp.length);

    return tmp;
  }

  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(timeStampAndCRLs.length);

    for (int i = 0; i != timeStampAndCRLs.length; i++) {
      v.add(timeStampAndCRLs[i]);
    }

    return new DERSequence(v);
  }

}