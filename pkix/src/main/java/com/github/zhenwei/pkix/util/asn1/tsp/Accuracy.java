package com.github.zhenwei.pkix.util.asn1.tsp;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERTaggedObject;


public class Accuracy
    extends ASN1Object {

  ASN1Integer seconds;

  ASN1Integer millis;

  ASN1Integer micros;

  // constantes
  protected static final int MIN_MILLIS = 1;

  protected static final int MAX_MILLIS = 999;

  protected static final int MIN_MICROS = 1;

  protected static final int MAX_MICROS = 999;

  protected Accuracy() {
  }

  public Accuracy(
      ASN1Integer seconds,
      ASN1Integer millis,
      ASN1Integer micros) {
    if (null != millis) {
      int millisValue = millis.intValueExact();
      if (millisValue < MIN_MILLIS || millisValue > MAX_MILLIS) {
        throw new IllegalArgumentException("Invalid millis field : not in (1..999)");
      }
    }
    if (null != micros) {
      int microsValue = micros.intValueExact();
      if (microsValue < MIN_MICROS || microsValue > MAX_MICROS) {
        throw new IllegalArgumentException("Invalid micros field : not in (1..999)");
      }
    }

    this.seconds = seconds;
    this.millis = millis;
    this.micros = micros;
  }

  private Accuracy(ASN1Sequence seq) {
    seconds = null;
    millis = null;
    micros = null;

    for (int i = 0; i < seq.size(); i++) {
      // seconds
      if (seq.getObjectAt(i) instanceof ASN1Integer) {
        seconds = (ASN1Integer) seq.getObjectAt(i);
      } else if (seq.getObjectAt(i) instanceof ASN1TaggedObject) {
        ASN1TaggedObject extra = (ASN1TaggedObject) seq.getObjectAt(i);

        switch (extra.getTagNo()) {
          case 0:
            millis = ASN1Integer.getInstance(extra, false);
            int millisValue = millis.intValueExact();
            if (millisValue < MIN_MILLIS || millisValue > MAX_MILLIS) {
              throw new IllegalArgumentException("Invalid millis field : not in (1..999)");
            }
            break;
          case 1:
            micros = ASN1Integer.getInstance(extra, false);
            int microsValue = micros.intValueExact();
            if (microsValue < MIN_MICROS || microsValue > MAX_MICROS) {
              throw new IllegalArgumentException("Invalid micros field : not in (1..999)");
            }
            break;
          default:
            throw new IllegalArgumentException("Invalid tag number");
        }
      }
    }
  }

  public static Accuracy getInstance(Object o) {
    if (o instanceof Accuracy) {
      return (Accuracy) o;
    }

    if (o != null) {
      return new Accuracy(ASN1Sequence.getInstance(o));
    }

    return null;
  }

  public ASN1Integer getSeconds() {
    return seconds;
  }

  public ASN1Integer getMillis() {
    return millis;
  }

  public ASN1Integer getMicros() {
    return micros;
  }

  /**
   * <pre>
   * Accuracy ::= SEQUENCE {
   *             seconds        INTEGER              OPTIONAL,
   *             millis     [0] INTEGER  (1..999)    OPTIONAL,
   *             micros     [1] INTEGER  (1..999)    OPTIONAL
   *             }
   * </pre>
   */
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(3);

    if (seconds != null) {
      v.add(seconds);
    }

    if (millis != null) {
      v.add(new DERTaggedObject(false, 0, millis));
    }

    if (micros != null) {
      v.add(new DERTaggedObject(false, 1, micros));
    }

    return new DERSequence(v);
  }
}