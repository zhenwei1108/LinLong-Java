package com.github.zhenwei.pkix.util.asn1.cmp;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;
import java.util.Enumeration;

public class ErrorMsgContent
    extends ASN1Object {

  private PKIStatusInfo pkiStatusInfo;
  private ASN1Integer errorCode;
  private PKIFreeText errorDetails;

  private ErrorMsgContent(ASN1Sequence seq) {
    Enumeration en = seq.getObjects();

    pkiStatusInfo = PKIStatusInfo.getInstance(en.nextElement());

    while (en.hasMoreElements()) {
      Object o = en.nextElement();

      if (o instanceof ASN1Integer) {
        errorCode = ASN1Integer.getInstance(o);
      } else {
        errorDetails = PKIFreeText.getInstance(o);
      }
    }
  }

  public static ErrorMsgContent getInstance(Object o) {
    if (o instanceof ErrorMsgContent) {
      return (ErrorMsgContent) o;
    }

    if (o != null) {
      return new ErrorMsgContent(ASN1Sequence.getInstance(o));
    }

    return null;
  }

  public ErrorMsgContent(PKIStatusInfo pkiStatusInfo) {
    this(pkiStatusInfo, null, null);
  }

  public ErrorMsgContent(
      PKIStatusInfo pkiStatusInfo,
      ASN1Integer errorCode,
      PKIFreeText errorDetails) {
    if (pkiStatusInfo == null) {
      throw new IllegalArgumentException("'pkiStatusInfo' cannot be null");
    }

    this.pkiStatusInfo = pkiStatusInfo;
    this.errorCode = errorCode;
    this.errorDetails = errorDetails;
  }

  public PKIStatusInfo getPKIStatusInfo() {
    return pkiStatusInfo;
  }

  public ASN1Integer getErrorCode() {
    return errorCode;
  }

  public PKIFreeText getErrorDetails() {
    return errorDetails;
  }

  /**
   * <pre>
   * ErrorMsgContent ::= SEQUENCE {
   *                        pKIStatusInfo          PKIStatusInfo,
   *                        errorCode              INTEGER           OPTIONAL,
   *                        -- implementation-specific error codes
   *                        errorDetails           PKIFreeText       OPTIONAL
   *                        -- implementation-specific error details
   * }
   * </pre>
   *
   * @return a basic ASN.1 object representation.
   */
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(3);

    v.add(pkiStatusInfo);
    addOptional(v, errorCode);
    addOptional(v, errorDetails);

    return new DERSequence(v);
  }

  private void addOptional(ASN1EncodableVector v, ASN1Encodable obj) {
    if (obj != null) {
      v.add(obj);
    }
  }
}