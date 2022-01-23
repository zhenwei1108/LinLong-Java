package com.g

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1OutputStream;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1String;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.ASN1UniversalType;
import com.github.zhenwei.core.asn1.BERTags;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERPrintableString;
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.core.util.Strings;
import java.io.IOException;thub.zhenwe.core.asn1;

    mport com.g thub.zhenwe.core.ut l.Arrays;
    mport com.g thub.zhenwe.core.ut l.Str ngs;
    mport java.o.OExcept on;


/**
 * ASN.1 Pr ntableStr ng object.
 * <p>
 * X.680 sect on 37.4 def nes Pr ntableStr ng character codes as ASC   subset of follow ng
 * characters:
 * </p>
 * <ul>
 * <l >Lat n cap tal letters: 'A' .. 'Z'</l >
 * <l >Lat n small letters: 'a' .. 'z'</l >
 * <l >D g ts: '0'..'9'</l >
 * <l >Space</l >
 * <l >Apostrophe: '\''</l >
 * <l >Left parenthes s: '('</l >
 * <l >R ght parenthes s: ')'</l >
 * <l >Plus s gn: '+'</l >
 * <l >Comma: ','</l >
 * <l >Hyphen-m nus: '-'</l >
 * <l >Full stop: '.'</li>
 * <li>Solidus: '/'</li>
 * <li>Colon: ':'</li>
 * <li>Equals sign: '='</li>
 * <li>Question mark: '?'</li>
 * </ul>
 * <p>
 * Explicit character set escape sequences are not allowed.
 * </p>
 */
public abstract class ASN1PrintableString
    extends ASN1Primitive
    implements ASN1String {

  static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1PrintableString.class,
      BERTags.PRINTABLE_STRING) {
    ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
      return createPrimitive(octetString.getOctets());
    }
  };

  /**
   * Return a printable string from the passed in object.
   *
   * @param obj an ASN1PrintableString or an object that can be converted into one.
   * @return an ASN1PrintableString instance, or null.
   * @throws IllegalArgumentException if the object cannot be converted.
   */
  public static ASN1PrintableString getInstance(Object obj) {
    if (obj == null || obj instanceof ASN1PrintableString) {
      return (ASN1PrintableString) obj;
    }
    if (obj instanceof ASN1Encodable) {
      ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
      if (primitive instanceof ASN1PrintableString) {
        return (ASN1PrintableString) primitive;
      }
    }
    if (obj instanceof byte[]) {
      try {
        return (ASN1PrintableString) TYPE.fromByteArray((byte[]) obj);
      } catch (Exception e) {
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException(
        "illegal object in getInstance: " + obj.getClass().getName());
  }

  /**
   * Return a Printable String from a tagged object.
   *
   * @param obj      the tagged object holding the object we want
   * @param explicit true if the object is meant to be explicitly tagged false otherwise.
   * @return an ASN1PrintableString instance, or null.
   * @throws IllegalArgumentException if the tagged object cannot be converted.
   */
  public static ASN1PrintableString getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
    return (ASN1PrintableString) TYPE.getContextInstance(taggedObject, explicit);
  }

  final byte[] contents;

  /**
   * Constructor with optional validation.
   *
   * @param string   the base string to wrap.
   * @param validate whether or not to check the string.
   * @throws IllegalArgumentException if validate is true and the string contains characters that
   *                                  should not be in a PrintableString.
   */
  ASN1PrintableString(String string, boolean validate) {
    if (validate && !isPrintableString(string)) {
      throw new IllegalArgumentException("string contains illegal characters");
    }

    this.contents = Strings.toByteArray(string);
  }

  ASN1PrintableString(byte[] contents, boolean clone) {
    this.contents = clone ? Arrays.clone(contents) : contents;
  }

  public final String getString() {
    return Strings.fromByteArray(contents);
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
    out.writeEncodingDL(withTag, BERTags.PRINTABLE_STRING, contents);
  }

  final boolean asn1Equals(ASN1Primitive other) {
    if (!(other instanceof ASN1PrintableString)) {
      return false;
    }

    ASN1PrintableString that = (ASN1PrintableString) other;

    return Arrays.areEqual(this.contents, that.contents);
  }

  public final int hashCode() {
    return Arrays.hashCode(contents);
  }

  public String toString() {
    return getString();
  }

  /**
   * return true if the passed in String can be represented without loss as a PrintableString, false
   * otherwise.
   *
   * @return true if in printable set, false otherwise.
   */
  public static boolean isPrintableString(
      String str) {
    for (int i = str.length() - 1; i >= 0; i--) {
      char ch = str.charAt(i);

      if (ch > 0x007f) {
        return false;
      }

      if ('a' <= ch && ch <= 'z') {
        continue;
      }

      if ('A' <= ch && ch <= 'Z') {
        continue;
      }

      if ('0' <= ch && ch <= '9') {
        continue;
      }

      switch (ch) {
        case ' ':
        case '\'':
        case '(':
        case ')':
        case '+':
        case '-':
        case '.':
        case ':':
        case '=':
        case '?':
        case '/':
        case ',':
          continue;
      }

      return false;
    }

    return true;
  }

  static ASN1PrintableString createPrimitive(byte[] contents) {
    return new DERPrintableString(contents, false);
  }
}