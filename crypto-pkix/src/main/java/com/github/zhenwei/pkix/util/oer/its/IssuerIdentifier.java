package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Choice;
import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERTaggedObject;

/**
 * <pre>
 *     IssuerIdentifier ::= CHOICE {
 *         sha256AndDigest HashedId8,
 *         self HashAlgorithm,
 *         ...,
 *         sha384AndDigest HashedId8
 *     }
 * </pre>
 */
public class IssuerIdentifier
    extends ASN1Object
    implements ASN1Choice {

  public static final int sha256AndDigest = 0;
  public static final int self = 1;
  public static final int extension = 2;
  public static final int sha384AndDigest = 3;

  private final int choice;
  private final ASN1Encodable value;


  public IssuerIdentifier(int choice, ASN1Encodable value) {
    this.choice = choice;
    this.value = value;
  }

  public static IssuerIdentifier getInstance(Object choice) {
    if (choice instanceof IssuerIdentifier) {
      return (IssuerIdentifier) choice;
    } else {
      ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(choice);
      int item = taggedObject.getTagNo();

      switch (item) {
        case sha256AndDigest: // sha256AndDigest HashId8
          return new IssuerIdentifier(sha256AndDigest,
              HashedId.HashedId8.getInstance(taggedObject.getObject()));
        case self: // self HashAlgorithm
          return new IssuerIdentifier(self, HashAlgorithm.getInstance(taggedObject.getObject()));
        case extension: // sha384AndDigest  HashedId8
          return new IssuerIdentifier(extension,
              DEROctetString.getInstance(taggedObject.getObject()));
        case sha384AndDigest: // sha384AndDigest  HashedId8
          return new IssuerIdentifier(sha384AndDigest,
              HashedId.HashedId8.getInstance(taggedObject.getObject()));
        default:
          throw new IllegalArgumentException("unable to decode into known choice" + item);
      }

    }
  }

  public static Builder builder() {
    return new Builder();
  }

  public boolean isSelf() {
    return choice == self;
  }

  public int getChoice() {
    return choice;
  }

  public ASN1Encodable getValue() {
    return value;
  }

  public ASN1Primitive toASN1Primitive() {
    return new DERTaggedObject(choice, value);
  }

  public static class Builder {

    public int choice;
    public ASN1Encodable value;

    public Builder setChoice(int choice) {
      this.choice = choice;
      return this;
    }

    public Builder setValue(ASN1Encodable value) {
      this.value = value;
      return this;
    }

    public Builder sha256AndDigest(HashedId id) {
      this.choice = sha256AndDigest;
      this.value = id;
      return this;
    }

    public Builder self(HashAlgorithm alg) {
      this.choice = self;
      this.value = alg;
      return this;
    }

    public Builder extension(byte[] ext) {
      this.choice = extension;
      this.value = new DEROctetString(ext);
      return this;
    }

    public Builder sha384AndDigest(HashedId id) {
      this.choice = sha384AndDigest;
      this.value = id;
      return this;
    }

    public IssuerIdentifier createIssuerIdentifier() {
      return new IssuerIdentifier(choice, value);
    }
  }


}