package com.github.zhenwei.core.asn1.x509;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1OutputStream;
import com.github.zhenwei.core.asn1.ASN1ParsingException;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1String;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.ASN1UniversalType;
import com.github.zhenwei.core.asn1.BERTags;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERUniversalString;
import com.github.zhenwei.core.util.Arrays;
import java.io.IOException;

/**
 * ASN.1 UniversalString object - encodes UNICODE (ISO 10646) characters using 32-bit format. In
 * Java we have no way of representing this directly so we rely on byte arrays to carry these.
 */
public abstract class ASN1UniversalString
    extends ASN1Primitive
    implements ASN1String {

  static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1UniversalString.class,
      BERTags.UNIVERSAL_STRING) {
    ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
      return createPrimitive(octetString.getOctets());
    }
  };

  private static final char[] table = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B',
      'C', 'D', 'E', 'F'};

  /**
   * Return a Universal String from the passed in object.
   *
   * @param obj an ASN1UniversalString or an object that can be converted into one.
   * @return an ASN1UniversalString instance, or null
   * @throws IllegalArgumentException if the object cannot be converted.
   */
  public static ASN1UniversalString getInstance(Object obj) {
    if (obj == null || obj instanceof ASN1UniversalString) {
      return (ASN1UniversalString) obj;
    }
    if (obj instanceof ASN1Encodable) {
      ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
      if (primitive instanceof ASN1UniversalString) {
        return (ASN1UniversalString) primitive;
      }
    }
    if (obj instanceof byte[]) {
      try {
        return (ASN1UniversalString) TYPE.fromByteArray((byte[]) obj);
      } catch (Exception e) {
        throw new IllegalArgumentException("encoding error getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException(
        "illegal object in getInstance: " + obj.getClass().getName());
  }

  /**
   * Return a Universal String from a tagged object.
   *
   * @param obj      the tagged object holding the object we want
   * @param explicit true if the object is meant to be explicitly tagged false otherwise.
   * @return a ASN1UniversalString instance, or null
   * @throws IllegalArgumentException if the tagged object cannot be converted.
   */
  public static ASN1UniversalString getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
    return (ASN1UniversalString) TYPE.getContextInstance(taggedObject, explicit);
  }

  final byte[] contents;

  ASN1UniversalString(byte[] contents, boolean clone) {
    this.contents = clone ? Arrays.clone(contents) : contents;
  }

  public final String getString() {
    StringBuffer buf = new StringBuffer("#");

    byte[] string;
    try {
      string = getEncoded();
    } catch (IOException e) {
      throw new ASN1ParsingException("internal error encoding UniversalString");
    }

    for (int i = 0; i != string.length; i++) {
      buf.append(table[(string[i] >>> 4) & 0xf]);
      buf.append(table[string[i] & 0xf]);
    }

    return buf.toString();
  }

  public String toString() {
    return getString();
  }

  public final byte[] getOctets() {
    return Arrays.clone(contents);
  }

  final boolean isConstructed() {
    return false;
  }

  final int encodedLength(boolean withTag) {
    return ASN1OutputStream.getLengthOfEncodingDL(withTag, contents.length);
  }

  final void encode(ASN1OutputStream out, boolean withTag) throws IOException {
    out.writeEncodingDL(withTag, BERTags.UNIVERSAL_STRING, contents);
  }

  final boolean asn1Equals(ASN1Primitive other) {
    if (!(other instanceof ASN1UniversalString)) {
      return false;
    }

    ASN1UniversalString that = (ASN1UniversalString) other;

    return Arrays.areEqual(this.contents, that.contents);
  }

  public final int hashCode() {
    return Arrays.hashCode(contents);
  }

  static ASN1UniversalString createPrimitive(byte[] contents) {
    return new DERUniversalString(contents, false);
  }
}