package com.github.zhenwei.pkix.util.oer;

import com.github.zhenwei.core.asn1.ASN1ApplicationSpecific;
import com.github.zhenwei.core.asn1.ASN1Boolean;
import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Enumerated;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.ASN1UTF8String;
import com.github.zhenwei.core.asn1.BERTags;
import com.github.zhenwei.core.asn1.DERBitString;
import com.github.zhenwei.core.util.BigIntegers;
import com.github.zhenwei.core.util.Pack;
import com.github.zhenwei.core.util.Strings;
import com.github.zhenwei.core.util.encoders.Hex;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Iterator;

public class OEROutputStream {

  private final OutputStream out;

  /**
   * Creates an output stream filter built on top of the specified underlying output stream.
   *
   * @param out the underlying output stream to be assigned to the field <tt>this.out</tt> for later
   *            use, or
   *            <code>null</code> if this instance is to be
   *            created without an underlying stream.
   */
  public static OEROutputStream create(OutputStream out) {
    return new OEROutputStream(out);
  }

  private static final int[] bits = new int[]{1, 2, 4, 8, 16, 32, 64, 128};

  OEROutputStream(OutputStream out) {
    this.out = out;
  }

  public void write(ASN1Encodable encodable, OERDefinition.Element oerElement)
      throws IOException {

    if (encodable == OEROptional.ABSENT) {
      return;
    } else if (encodable instanceof OEROptional) {
      write(((OEROptional) encodable).get(), oerElement);
      return;
    }

    encodable = encodable.toASN1Primitive();

    switch (oerElement.baseType) {

      case SEQ: {
        ASN1Sequence seq = ASN1Sequence.getInstance(encodable);

        // build mask.
        int j = 7;
        int mask = 0;

        if (oerElement.extensionsInDefinition) {
          if (oerElement.hasPopulatedExtension()) {
            mask |= bits[j];
          }
          j--;
        }

        //
        // Write optional bit mask.
        //

        for (int t = 0; t < oerElement.children.size(); t++) {
          OERDefinition.Element childOERDescription = oerElement.children.get(t);

          if (j < 0) {
            out.write(mask);
            j = 7;
            mask = 0;
          }

          ASN1Encodable asn1EncodableChild = seq.getObjectAt(t);
          if (childOERDescription.explicit && asn1EncodableChild instanceof OEROptional) {
            // TODO call stack like definition error.
            throw new IllegalStateException(
                "absent sequence element that is required by oer definition");
          }

          if (!childOERDescription.explicit) {
            ASN1Encodable obj = seq.getObjectAt(t);
            if (childOERDescription.getDefaultValue() != null) {

              if (obj instanceof OEROptional) {
                if (((OEROptional) obj).isDefined()) {
                  if (!((OEROptional) obj).get().equals(childOERDescription.defaultValue)) {
                    mask |= bits[j];
                  }
                }
              } else {
                if (!childOERDescription.getDefaultValue().equals(obj)) {
                  mask |= bits[j];
                }
              }


            } else {
              if (asn1EncodableChild != OEROptional.ABSENT) {
                mask |= bits[j];
              }
            }
            j--;
          }
        }

        if (j != 7) {
          out.write(mask);
        }
        //
        // Write the values
        //
        for (int t = 0; t < oerElement.children.size(); t++) {
          ASN1Encodable child = seq.getObjectAt(t);
          OERDefinition.Element childOERElement = oerElement.children.get(t);

          if (childOERElement.getDefaultValue() != null) {
            if (childOERElement.getDefaultValue().equals(child)) {
              continue;
            }
          }
          write(child, childOERElement);
        }
        out.flush();
        debugPrint(oerElement.appendLabel(""));
      }
      break;
      case SEQ_OF:
        //
        // Assume this comes in as a sequence.
        //
        Enumeration e;
        if (encodable instanceof ASN1Set) {
          e = ((ASN1Set) encodable).getObjects();
          encodeQuantity(((ASN1Set) encodable).size());
        } else if (encodable instanceof ASN1Sequence) {
          e = ((ASN1Sequence) encodable).getObjects();
          encodeQuantity(((ASN1Sequence) encodable).size());
        } else {
          throw new IllegalStateException("encodable at for SEQ_OF is not a container");
        }

        while (e.hasMoreElements()) {
          Object o = e.nextElement();
          write((ASN1Encodable) o, oerElement.getFirstChid());
        }
        out.flush();
        debugPrint(oerElement.appendLabel(""));
        break;
      case CHOICE: {
        ASN1Primitive item = encodable.toASN1Primitive();
        BitBuilder bb = new BitBuilder();
        int tag;

        if (item instanceof ASN1ApplicationSpecific) {
          //
          // Application specific tag prefix.
          //
          tag = ((ASN1ApplicationSpecific) item).getApplicationTag();
          bb.writeBit(0).writeBit(1);
          item = ((ASN1ApplicationSpecific) item).getEnclosedObject();
        } else if (item instanceof ASN1TaggedObject) {
          ASN1TaggedObject taggedObject = (ASN1TaggedObject) item;

          //
          // Tag prefix.
          //
          int tagClass = taggedObject.getTagClass();
          bb.writeBit(tagClass & BERTags.CONTEXT_SPECIFIC)
              .writeBit(tagClass & BERTags.APPLICATION);

          tag = taggedObject.getTagNo();
          item = taggedObject.getBaseObject().toASN1Primitive();
        } else {
          throw new IllegalStateException("only support tagged objects");
        }

        //
        // Encode tag value.
        //

        // Small tag value encode in remaining bits
        if (tag <= 63) {
          bb.writeBits(tag, 6);
        } else {
          // Large tag value variant.
          bb.writeBits(0xFF, 6);
          // Encode as 7bit bytes where MSB indicated continuing byte.
          bb.write7BitBytes(tag);
        }

        if (debugOutput != null) {
          if (item instanceof ASN1ApplicationSpecific) {
            debugPrint(oerElement.appendLabel("AS"));
          } else if (item instanceof ASN1TaggedObject) {
            debugPrint(oerElement.appendLabel("CS"));
          }
        }

        // Save the header.
        bb.writeAndClear(out);
        write(item, oerElement.children.get(tag));
        out.flush();
        break;
      }
      case ENUM: {
        BigInteger ordinal;
        if (encodable instanceof ASN1Integer) {
          ordinal = ASN1Integer.getInstance(encodable).getValue();
        } else {
          ordinal = ASN1Enumerated.getInstance(encodable).getValue();
        }

        for (Iterator it = oerElement.children.iterator(); it.hasNext(); ) {
          OERDefinition.Element child = (OERDefinition.Element) it.next();
          //
          // This by default is canonical OER, see NOTE 1 and NOTE 2, 11.14
          // Section 11.4 of T-REC-X.696-201508-I!!PDF-E.pdf
          //
          if (child.enumValue.equals(ordinal)) {
            if (ordinal.compareTo(BigInteger.valueOf(127)) > 0) {
              // Note 2 Section 11.4 of T-REC-X.696-201508-I!!PDF-E.pdf
              byte[] val = ordinal.toByteArray();
              int l = 0x80 | (val.length & 0xFF);
              out.write(l);
              out.write(val);
            } else {
              out.write(ordinal.intValue() & 0x7F);
            }
            out.flush();
            debugPrint(oerElement.appendLabel(oerElement.rangeExpression()));
            return;
          }
        }

        throw new IllegalArgumentException(
            "enum value " + ordinal + " " + Hex.toHexString(ordinal.toByteArray())
                + " no in defined child list");
      }
      case INT: {
        ASN1Integer integer = ASN1Integer.getInstance(encodable);

        // >0 = positive and <0 = negative
        int intBytesForRange = oerElement.intBytesForRange();
        if (intBytesForRange > 0) {
          //
          // For unsigned fixed length 1,2,4,8 byte integers.
          //
          byte[] encoded = BigIntegers.asUnsignedByteArray(intBytesForRange, integer.getValue());
          switch (intBytesForRange) {
            case 1:
            case 2:
            case 4:
            case 8:
              out.write(encoded);
              break;
            default:
              throw new IllegalStateException("unknown uint length " + intBytesForRange);
          }
        } else if (intBytesForRange < 0) {

          //
          // For twos compliment numbers of 1,2,4,8 bytes in encoded length.
          //

          byte[] encoded;
          BigInteger number = integer.getValue();
          switch (intBytesForRange) {
            case -1:
              encoded = new byte[]{BigIntegers.byteValueExact(number)};
              break;
            case -2:
              encoded = Pack.shortToBigEndian(BigIntegers.shortValueExact(number));
              break;
            case -4:
              encoded = Pack.intToBigEndian(BigIntegers.intValueExact(number));
              break;
            case -8:
              encoded = Pack.longToBigEndian(BigIntegers.longValueExact(number));
              break;
            default:
              throw new IllegalStateException("unknown twos compliment length");
          }

          out.write(encoded);
        } else {
          // Unbounded at one or both ends and needs length encoding.
          byte[] encoded;
          if (oerElement.isLowerRangeZero()) {
            // Since we have already captured the fixed with unsigned ints.
            // Everything is assumed unbounded we need to encode a length and write the value.
            encoded = BigIntegers.asUnsignedByteArray(integer.getValue());
          } else {
            // Twos complement
            encoded = integer.getValue().toByteArray();
          }

          encodeLength(encoded.length); // Deals with long and short forms.
          out.write(encoded);
        }
        debugPrint(oerElement.appendLabel(oerElement.rangeExpression()));
        out.flush();
      }

      break;
      case OCTET_STRING: {
        ASN1OctetString octets = ASN1OctetString.getInstance(encodable);
        byte[] bytes = octets.getOctets();
        if (oerElement.isFixedLength()) {
          out.write(bytes);
        } else {
          encodeLength(bytes.length);
          out.write(bytes);
        }
        debugPrint(oerElement.appendLabel(oerElement.rangeExpression()));
        out.flush();
        break;
      }
      case UTF8_STRING: {
        ASN1UTF8String utf8 = ASN1UTF8String.getInstance(encodable);
        byte[] encoded = Strings.toUTF8ByteArray(utf8.getString());
        encodeLength(encoded.length);
        out.write(encoded);
        debugPrint(oerElement.appendLabel(""));
        out.flush();
        break;
      }
      case BIT_STRING: {

        DERBitString bitString = DERBitString.getInstance(encodable);
        byte[] bytes = bitString.getBytes();
        if (oerElement.isFixedLength()) {
          out.write(bytes);
          debugPrint(oerElement.appendLabel(oerElement.rangeExpression()));
        } else {
          int padBits = bitString.getPadBits();
          encodeLength(bytes.length + 1); // 13.3.1
          out.write(padBits); // 13.3.2
          out.write(bytes); // 13.3.3
          debugPrint(oerElement.appendLabel(oerElement.rangeExpression()));
        }
        out.flush();
      }
      break;
      case NULL:
        // Does not encode in OER.
        break;
      case EXTENSION: {
        ASN1OctetString octets = ASN1OctetString.getInstance(encodable);
        byte[] bytes = octets.getOctets();
        if (oerElement.isFixedLength()) {
          out.write(bytes);
        } else {
          encodeLength(bytes.length);
          out.write(bytes);
        }
        debugPrint(oerElement.appendLabel(oerElement.rangeExpression()));
        out.flush();
        break;
      }

      case ENUM_ITEM:
        // Used to define options does not encode.
        break;
      case BOOLEAN:
        debugPrint(oerElement.label);
        ASN1Boolean asn1Boolean = ASN1Boolean.getInstance(encodable);
        if (asn1Boolean.isTrue()) {
          out.write(255);
        } else {
          out.write(0);
        }
        out.flush();
    }

  }


  protected PrintWriter debugOutput = null;

  protected void debugPrint(String what) {

    if (debugOutput != null) {

      StackTraceElement[] callStack = Thread.currentThread().getStackTrace();
      int level = -1;
      for (int i = 0; i != callStack.length; i++) {
        StackTraceElement ste = callStack[i];
        if (ste.getMethodName().equals("debugPrint")) {
          level = 0;
          continue;
        }
        if (ste.getClassName().contains("OERInput")) {
          level++;
        }
      }

      for (; level > 0; level--) {
        debugOutput.append("    ");
      }
      debugOutput.append(what).append("\n");
      debugOutput.flush();
    }
  }


  private void encodeLength(long len)
      throws IOException {
    if (len <= 127) // complies with 31.2
    {
      out.write((int) len); // short form 8.6.3
    } else {
      // Long form,
      byte[] value = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(len));
      out.write((value.length | 0x80));
      out.write(value);
    }
  }

  private void encodeQuantity(long quantity)
      throws IOException {
    byte[] quantityEncoded = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(quantity));
    out.write(quantityEncoded.length);
    out.write(quantityEncoded);
  }


  public static int byteLength(long value) {
    long m = 0xFF00000000000000L;
    int j = 8;
    for (; j > 0 && (value & m) == 0; j--) {
      value <<= 8;
    }
    return j;
  }

}