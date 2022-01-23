package com.github.zhenwei.core.asn1;


import java.io.IOException;
import java.util.Enumeration;
import java.util.NoSuchElementException;

/**
 * ASN.1 OctetStrings, with indefinite length rules, and <i>constructed form</i> support.
 * <p>
 * The Basic Encoding Rules (BER) format allows encoding using so called "<i>constructed form</i>",
 * which DER and CER formats forbid allowing only "primitive form".
 * </p><p>
 * This class <b>always</b> produces the constructed form with underlying segments in an indefinite
 * length array.  If the input wasn't the same, then this output is not faithful reproduction.
 * </p>
 * <p>
 * See {@link ASN1OctetString} for X.690 encoding rules of OCTET-STRING objects.
 * </p>
 */
public class BEROctetString
    extends ASN1OctetString {

  private static final int DEFAULT_SEGMENT_LIMIT = 1000;

  private final int segmentLimit;
  private final ASN1OctetString[] elements;

  /**
   * Convert a vector of octet strings into a single byte string
   */
  static byte[] flattenOctetStrings(ASN1OctetString[] octetStrings) {
    int count = octetStrings.length;
    switch (count) {
      case 0:
        return EMPTY_OCTETS;
      case 1:
        return octetStrings[0].string;
      default: {
        int totalOctets = 0;
        for (int i = 0; i < count; ++i) {
          totalOctets += octetStrings[i].string.length;
        }

        byte[] string = new byte[totalOctets];
        for (int i = 0, pos = 0; i < count; ++i) {
          byte[] octets = octetStrings[i].string;
          System.arraycopy(octets, 0, string, pos, octets.length);
          pos += octets.length;
        }

//            assert pos == totalOctets;
        return string;
      }
    }
  }

  /**
   * Create an OCTET-STRING object from a byte[]
   *
   * @param string the octets making up the octet string.
   */
  public BEROctetString(byte[] string) {
    this(string, DEFAULT_SEGMENT_LIMIT);
  }

  /**
   * Multiple {@link ASN1OctetString} data blocks are input, the result is <i>constructed form</i>.
   *
   * @param elements an array of OCTET STRING to construct the BER OCTET STRING from.
   */
  public BEROctetString(ASN1OctetString[] elements) {
    this(elements, DEFAULT_SEGMENT_LIMIT);
  }

  /**
   * Create an OCTET-STRING object from a byte[]
   *
   * @param string       the octets making up the octet string.
   * @param segmentLimit the number of octets stored in each DER encoded component OCTET STRING.
   */
  public BEROctetString(byte[] string, int segmentLimit) {
    this(string, null, segmentLimit);
  }

  /**
   * Multiple {@link ASN1OctetString} data blocks are input, the result is <i>constructed form</i>.
   *
   * @param elements     an array of OCTET STRING to construct the BER OCTET STRING from.
   * @param segmentLimit the number of octets stored in each DER encoded component OCTET STRING.
   */
  public BEROctetString(ASN1OctetString[] elements, int segmentLimit) {
    this(flattenOctetStrings(elements), elements, segmentLimit);
  }

  private BEROctetString(byte[] string, ASN1OctetString[] elements, int segmentLimit) {
    super(string);
    this.elements = elements;
    this.segmentLimit = segmentLimit;
  }

  /**
   * Return the OCTET STRINGs that make up this string.
   *
   * @return an Enumeration of the component OCTET STRINGs.
   * @deprecated Will be removed.
   */
  public Enumeration getObjects() {
    if (elements == null) {
      return new Enumeration() {
        int pos = 0;

        public boolean hasMoreElements() {
          return pos < string.length;
        }

        public Object nextElement() {
          if (pos < string.length) {
            int length = Math.min(string.length - pos, segmentLimit);
            byte[] segment = new byte[length];
            System.arraycopy(string, pos, segment, 0, length);
            pos += length;
            return new DEROctetString(segment);
          }
          throw new NoSuchElementException();
        }
      };
    }

    return new Enumeration() {
      int counter = 0;

      public boolean hasMoreElements() {
        return counter < elements.length;
      }

      public Object nextElement() {
        if (counter < elements.length) {
          return elements[counter++];
        }
        throw new NoSuchElementException();
      }
    };
  }

  boolean isConstructed() {
    return null != elements || string.length > segmentLimit;
  }

  int encodedLength(boolean withTag)
      throws IOException {
    if (!isConstructed()) {
      return DEROctetString.encodedLength(withTag, string.length);
    }

    int totalLength = withTag ? 4 : 3;

    if (null != elements) {
      for (int i = 0; i < elements.length; ++i) {
        totalLength += elements[i].encodedLength(true);
      }
    } else {
      int fullSegments = string.length / segmentLimit;
      totalLength += fullSegments * DEROctetString.encodedLength(true, segmentLimit);

      int lastSegmentLength = string.length - (fullSegments * segmentLimit);
      if (lastSegmentLength > 0) {
        totalLength += DEROctetString.encodedLength(true, lastSegmentLength);
      }
    }

    return totalLength;
  }

  void encode(ASN1OutputStream out, boolean withTag) throws IOException {
    if (!isConstructed()) {
      DEROctetString.encode(out, withTag, string, 0, string.length);
      return;
    }

    if (withTag) {
      out.write(BERTags.CONSTRUCTED | BERTags.OCTET_STRING);
    }
    out.write(0x80);

    if (null != elements) {
      out.writePrimitives(elements);
    } else {
      int pos = 0;
      while (pos < string.length) {
        int segmentLength = Math.min(string.length - pos, segmentLimit);
        DEROctetString.encode(out, true, string, pos, segmentLength);
        pos += segmentLength;
      }
    }

    out.write(0x00);
    out.write(0x00);
  }
}