package com.github.zhenwei.core.asn1;

import java.io.IOException;

/**
 * Parser for definite-length tagged objects.
 */
class DLTaggedObjectParser
    extends BERTaggedObjectParser {

  private final boolean _constructed;

  DLTaggedObjectParser(int tagClass, int tagNo, boolean constructed, ASN1StreamParser parser) {
    super(tagClass, tagNo, parser);

    _constructed = constructed;
  }

  /**
   * Return true if this tagged object is marked as constructed.
   *
   * @return true if constructed, false otherwise.
   */
  public boolean isConstructed() {
    return _constructed;
  }

  /**
   * Return an in-memory, encodable, representation of the tagged object.
   *
   * @return an ASN1TaggedObject.
   * @throws IOException if there is an issue loading the data.
   */
  public ASN1Primitive getLoadedObject()
      throws IOException {
    return _parser.loadTaggedDL(_tagClass, _tagNo, _constructed);
  }

  public ASN1Encodable parseBaseUniversal(boolean declaredExplicit, int baseTagNo)
      throws IOException {
    if (declaredExplicit) {
      if (!_constructed) {
        throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
      }

      return _parser.parseObject(baseTagNo);
    }

    return _constructed
        ? _parser.parseImplicitConstructedDL(baseTagNo)
        : _parser.parseImplicitPrimitive(baseTagNo);
  }

  public ASN1Encodable parseExplicitBaseObject() throws IOException {
    if (!_constructed) {
      throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
    }

    return _parser.readObject();
  }

  public ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException {
    if (!_constructed) {
      throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
    }

    return _parser.parseTaggedObject();
  }

  public ASN1TaggedObjectParser parseImplicitBaseTagged(int baseTagClass, int baseTagNo)
      throws IOException {
    // TODO[asn1] Special handling can be removed once ASN1ApplicationSpecific types removed.
    if (BERTags.APPLICATION == baseTagClass) {
      // This cast is ensuring the current user-expected return type.
      return (DLApplicationSpecific) _parser.loadTaggedDL(baseTagClass, baseTagNo, _constructed);
    }

    return new DLTaggedObjectParser(baseTagClass, baseTagNo, _constructed, _parser);
  }
}