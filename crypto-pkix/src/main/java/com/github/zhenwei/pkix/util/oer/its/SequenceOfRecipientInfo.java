package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * <pre>
 *     SequenceOfRecipientInfo ::= SEQUENCE OF RecipientInfo
 * </pre>
 */
public class SequenceOfRecipientInfo
    extends ASN1Object {

  private final List<RecipientInfo> recipientInfos;

  public SequenceOfRecipientInfo(List<RecipientInfo> recipientInfos) {
    this.recipientInfos = Collections.unmodifiableList(recipientInfos);
  }

  public static SequenceOfRecipientInfo getInstance(Object object) {

    if (object instanceof SequenceOfRecipientInfo) {
      return (SequenceOfRecipientInfo) object;
    }

    ASN1Sequence sequence = ASN1Sequence.getInstance(object);
    Enumeration enumeration = sequence.getObjects();
    ArrayList<RecipientInfo> infoArrayList = new ArrayList<RecipientInfo>();
    while (enumeration.hasMoreElements()) {
      infoArrayList.add(RecipientInfo.getInstance(enumeration.nextElement()));
    }
    return new Builder().setRecipientInfos(infoArrayList).createSequenceOfRecipientInfo();
  }

  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();

    return new DERSequence(v);
  }

  public List<RecipientInfo> getRecipientInfos() {
    return recipientInfos;
  }

  public static class Builder {

    private List<RecipientInfo> recipientInfos;

    public Builder setRecipientInfos(List<RecipientInfo> recipientInfos) {
      this.recipientInfos = recipientInfos;
      return this;
    }

    public Builder addRecipients(RecipientInfo... items) {
      if (recipientInfos == null) {
        recipientInfos = new ArrayList<RecipientInfo>();
      }
      recipientInfos.addAll(Arrays.asList(items));
      return this;
    }


    public SequenceOfRecipientInfo createSequenceOfRecipientInfo() {
      return new SequenceOfRecipientInfo(recipientInfos);
    }
  }

}