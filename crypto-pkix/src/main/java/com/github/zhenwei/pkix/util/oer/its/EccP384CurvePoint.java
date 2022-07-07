package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Null;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERNull;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERTaggedObject;
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.core.util.BigIntegers;
import java.math.BigInteger;

/**
 * EccP384CurvePoint ::= CHOICE  { x-only          OCTET STRING (SIZE (48)), fill            NULL,
 * compressed-y-0  OCTET STRING (SIZE (48)), compressed-y-1  OCTET STRING (SIZE (48)),
 * uncompressedP384 SEQUENCE { x OCTET STRING (SIZE (48)), y OCTET STRING (SIZE (48)) } }
 */
public class EccP384CurvePoint
    extends EccCurvePoint {

  public static final int xOnly = 0;
  public static final int fill = 1;
  public static final int compressedY0 = 2;
  public static final int compressedY1 = 3;
  public static final int uncompressedP384 = 4;


  private final int choice;
  private final ASN1Encodable value;

  public EccP384CurvePoint(int choice, ASN1Encodable value) {
    this.choice = choice;
    this.value = value;
  }

  public static EccP384CurvePoint getInstance(Object object) {
    if (object instanceof EccP384CurvePoint) {
      return (EccP384CurvePoint) object;
    }

    ASN1TaggedObject ato = ASN1TaggedObject.getInstance(object);
    ASN1Encodable value;
    switch (ato.getTagNo()) {
      case fill:
        value = ASN1Null.getInstance(ato.getObject());
        break;
      case xOnly:
      case compressedY0:
      case compressedY1:
        value = ASN1OctetString.getInstance(ato.getObject());
        break;
      case uncompressedP384:
        value = ASN1Sequence.getInstance(ato.getObject());
        break;
      default:
        throw new IllegalArgumentException("unknown tag " + ato.getTagNo());
    }

    return new Builder().setChoice(ato.getTagNo()).setValue(value).createEccP384CurvePoint();
  }

  public static Builder builder() {
    return new Builder();
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

  public byte[] getEncodedPoint() {
    byte[] key;
    switch (choice) {
      case compressedY0: {
        byte[] originalKey = DEROctetString.getInstance(value).getOctets();
        key = new byte[originalKey.length + 1];
        key[0] = 0x02;
        System.arraycopy(originalKey, 0, key, 1, originalKey.length);
      }
      break;
      case compressedY1: {
        byte[] originalKey = DEROctetString.getInstance(value).getOctets();
        key = new byte[originalKey.length + 1];
        key[0] = 0x03;
        System.arraycopy(originalKey, 0, key, 1, originalKey.length);
      }
      break;
      case uncompressedP384:
        ASN1Sequence sequence = ASN1Sequence.getInstance(value);
        byte[] x = DEROctetString.getInstance(sequence.getObjectAt(0)).getOctets();
        byte[] y = DEROctetString.getInstance(sequence.getObjectAt(1)).getOctets();
        key = Arrays.concatenate(new byte[]{0x04}, x, y);
        break;
      case xOnly:
        throw new IllegalStateException("x Only not implemented");
      default:
        throw new IllegalStateException("unknown point choice");
    }

    return key;

  }

  public static class Builder {

    private int choice;
    private ASN1Encodable value;

    Builder setChoice(int choice) {
      this.choice = choice;
      return this;
    }

    Builder setValue(ASN1Encodable value) {
      this.value = value;
      return this;
    }

    public EccP384CurvePoint createXOnly(BigInteger x) {
      this.choice = xOnly;
      this.value = new DEROctetString(BigIntegers.asUnsignedByteArray(x));
      return this.createEccP384CurvePoint();
    }

    public EccP384CurvePoint createFill() {
      this.choice = fill;
      this.value = DERNull.INSTANCE;
      return this.createEccP384CurvePoint();
    }

    public EccP384CurvePoint createCompressedY0(BigInteger y) {
      this.choice = compressedY0;
      throw new IllegalStateException("not fully implemented.");
    }

    public EccP384CurvePoint createCompressedY1(BigInteger y) {
      this.choice = compressedY1;
      throw new IllegalStateException("not fully implemented.");
    }

    public EccP384CurvePoint createUncompressedP384(BigInteger x, BigInteger y) {
      choice = uncompressedP384;
      value = new DERSequence(new ASN1Encodable[]{
          new DEROctetString(BigIntegers.asUnsignedByteArray(48, x)),
          new DEROctetString(BigIntegers.asUnsignedByteArray(48, y)),
      });
      return this.createEccP384CurvePoint();
    }

    private EccP384CurvePoint createEccP384CurvePoint() {
      return new EccP384CurvePoint(choice, value);
    }
  }
}