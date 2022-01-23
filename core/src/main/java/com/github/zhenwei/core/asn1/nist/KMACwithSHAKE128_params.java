package com.github.zhenwei.core.asn1.nist;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.util.Arrays;

/**
 * <pre>
 *   KMACwithSHAKE128-params ::= SEQUENCE {
 *      kMACOutputLength     INTEGER DEFAULT 256, -- Output length in bits
 *      customizationString  OCTET STRING DEFAULT ''H
 *    }
 * </pre>
 */
public class KMACwithSHAKE128_params
    extends ASN1Object {

  private static final byte[] EMPTY_STRING = new byte[0];
  private static final int DEF_LENGTH = 256;

  private final int outputLength;
  private final byte[] customizationString;

  public KMACwithSHAKE128_params(int outputLength) {
    this.outputLength = outputLength;
    this.customizationString = EMPTY_STRING;
  }

  public KMACwithSHAKE128_params(int outputLength, byte[] customizationString) {
    this.outputLength = outputLength;
    this.customizationString = Arrays.clone(customizationString);
  }

  public static nist.KMACwithSHAKE128_params getInstance(Object o) {
    if (o instanceof nist.KMACwithSHAKE128_params) {
      return (nist.KMACwithSHAKE128_params) o;
    } else if (o != null) {
      return new nist.KMACwithSHAKE128_params(ASN1Sequence.getInstance(o));
    }

    return null;
  }

  private KMACwithSHAKE128_params(ASN1Sequence seq) {
    if (seq.size() > 2) {
      throw new IllegalArgumentException("sequence size greater than 2");
    }

    if (seq.size() == 2) {
      this.outputLength = ASN1Integer.getInstance(seq.getObjectAt(0)).intValueExact();
      this.customizationString = Arrays.clone(
          ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());
    } else if (seq.size() == 1) {
      if (seq.getObjectAt(0) instanceof ASN1Integer) {
        this.outputLength = ASN1Integer.getInstance(seq.getObjectAt(0)).intValueExact();
        this.customizationString = EMPTY_STRING;
      } else {
        this.outputLength = DEF_LENGTH;
        this.customizationString = Arrays.clone(
            ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
      }
    } else {
      this.outputLength = DEF_LENGTH;
      this.customizationString = EMPTY_STRING;
    }
  }

  public int getOutputLength() {
    return outputLength;
  }

  public byte[] getCustomizationString() {
    return Arrays.clone(customizationString);
  }

  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();

    if (outputLength != DEF_LENGTH) {
      v.add(new ASN1Integer(outputLength));
    }

    if (customizationString.length != 0) {
      v.add(new DEROctetString(getCustomizationString()));
    }

    return new DERSequence(v);
  }
}