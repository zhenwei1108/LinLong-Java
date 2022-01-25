package com.github.zhenwei.pkix.util.asn1.cmp;

import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;

public class RevReqContent
    extends ASN1Object {

  private ASN1Sequence content;

  private RevReqContent(ASN1Sequence seq) {
    content = seq;
  }

  public static RevReqContent getInstance(Object o) {
    if (o instanceof RevReqContent) {
      return (RevReqContent) o;
    }

    if (o != null) {
      return new RevReqContent(ASN1Sequence.getInstance(o));
    }

    return null;
  }

  public RevReqContent(RevDetails revDetails) {
    this.content = new DERSequence(revDetails);
  }

  public RevReqContent(RevDetails[] revDetailsArray) {
    this.content = new DERSequence(revDetailsArray);
  }

  public RevDetails[] toRevDetailsArray() {
    RevDetails[] result = new RevDetails[content.size()];

    for (int i = 0; i != result.length; i++) {
      result[i] = RevDetails.getInstance(content.getObjectAt(i));
    }

    return result;
  }

  /**
   * <pre>
   * RevReqContent ::= SEQUENCE OF RevDetails
   * </pre>
   *
   * @return a basic ASN.1 object representation.
   */
  public ASN1Primitive toASN1Primitive() {
    return content;
  }
}