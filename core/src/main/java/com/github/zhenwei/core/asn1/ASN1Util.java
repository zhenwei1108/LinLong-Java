package com.github.zhenwei.core.asn1;

import java.io.IOException;

public abstract class ASN1Util {
  /*
   * Tag text methods
   */

  public static String getTagText(ASN1Tag tag) {
    return getTagText(tag.getTagClass(), tag.getTagNumber());
  }

  public static String getTagText(ASN1TaggedObject taggedObject) {
    return getTagText(taggedObject.getTagClass(), taggedObject.getTagNo());
  }

  public static String getTagText(ASN1TaggedObjectParser taggedObjectParser) {
    return getTagText(taggedObjectParser.getTagClass(), taggedObjectParser.getTagNo());
  }

  public static String getTagText(int tagClass, int tagNo) {
    switch (tagClass) {
      case BERTags.APPLICATION:
        return "[APPLICATION " + tagNo + "]";
      case BERTags.CONTEXT_SPECIFIC:
        return "[CONTEXT " + tagNo + "]";
      case BERTags.PRIVATE:
        return "[PRIVATE " + tagNo + "]";
      default:
        return "[UNIVERSAL " + tagNo + "]";
    }
  }


  /*
   * Wrappers for ASN1TaggedObject#getExplicitBaseObject
   */

  public static ASN1Object getExplicitBaseObject(ASN1TaggedObject taggedObject, int tagClass,
      int tagNo) {
    if (!taggedObject.hasTag(tagClass, tagNo)) {
      String expected = getTagText(tagClass, tagNo);
      String found = getTagText(taggedObject);
      throw new IllegalStateException("Expected " + expected + " tag but found " + found);
    }

    return taggedObject.getExplicitBaseObject();
  }

  public static ASN1Object getExplicitContextBaseObject(ASN1TaggedObject taggedObject, int tagNo) {
    return getExplicitBaseObject(taggedObject, BERTags.CONTEXT_SPECIFIC, tagNo);
  }

  public static ASN1Object tryGetExplicitBaseObject(ASN1TaggedObject taggedObject, int tagClass,
      int tagNo) {
    if (!taggedObject.hasTag(tagClass, tagNo)) {
      return null;
    }

    return taggedObject.getExplicitBaseObject();
  }

  public static ASN1Object tryGetExplicitContextBaseObject(ASN1TaggedObject taggedObject,
      int tagNo) {
    return tryGetExplicitBaseObject(taggedObject, BERTags.CONTEXT_SPECIFIC, tagNo);
  }


  /*
   * Wrappers for ASN1TaggedObject#getExplicitBaseTagged
   */

  public static ASN1TaggedObject getExplicitBaseTagged(ASN1TaggedObject taggedObject, int tagClass,
      int tagNo) {
    if (!taggedObject.hasTag(tagClass, tagNo)) {
      String expected = getTagText(tagClass, tagNo);
      String found = getTagText(taggedObject);
      throw new IllegalStateException("Expected " + expected + " tag but found " + found);
    }

    return taggedObject.getExplicitBaseTagged();
  }

  public static ASN1TaggedObject getExplicitContextBaseTagged(ASN1TaggedObject taggedObject,
      int tagNo) {
    return getExplicitBaseTagged(taggedObject, BERTags.CONTEXT_SPECIFIC, tagNo);
  }

  public static ASN1TaggedObject tryGetExplicitBaseTagged(ASN1TaggedObject taggedObject,
      int tagClass, int tagNo) {
    if (!taggedObject.hasTag(tagClass, tagNo)) {
      return null;
    }

    return taggedObject.getExplicitBaseTagged();
  }

  public static ASN1TaggedObject tryGetExplicitContextBaseTagged(ASN1TaggedObject taggedObject,
      int tagNo) {
    return tryGetExplicitBaseTagged(taggedObject, BERTags.CONTEXT_SPECIFIC, tagNo);
  }


  /*
   * Wrappers for ASN1TaggedObject#getBaseUniversal
   */

  public static ASN1Primitive getBaseUniversal(ASN1TaggedObject taggedObject, int tagClass,
      int tagNo,
      boolean declaredExplicit, int baseTagNo) {
    if (!taggedObject.hasTag(tagClass, tagNo)) {
      String expected = getTagText(tagClass, tagNo);
      String found = getTagText(taggedObject);
      throw new IllegalStateException("Expected " + expected + " tag but found " + found);
    }

    return taggedObject.getBaseUniversal(declaredExplicit, baseTagNo);
  }

  public static ASN1Primitive getContextBaseUniversal(ASN1TaggedObject taggedObject, int tagNo,
      boolean declaredExplicit, int baseTagNo) {
    return getBaseUniversal(taggedObject, BERTags.CONTEXT_SPECIFIC, tagNo, declaredExplicit,
        baseTagNo);
  }

  public static ASN1Primitive tryGetBaseUniversal(ASN1TaggedObject taggedObject, int tagClass,
      int tagNo,
      boolean declaredExplicit, int baseTagNo) {
    if (!taggedObject.hasTag(tagClass, tagNo)) {
      return null;
    }

    return taggedObject.getBaseUniversal(declaredExplicit, baseTagNo);
  }

  public static ASN1Primitive tryGetContextBaseUniversal(ASN1TaggedObject taggedObject, int tagNo,
      boolean declaredExplicit, int baseTagNo) {
    return tryGetBaseUniversal(taggedObject, BERTags.CONTEXT_SPECIFIC, tagNo, declaredExplicit,
        baseTagNo);
  }

//    /*
//     * Wrappers for ASN1TaggedObjectParser#parseBaseObject
//     */
//
//    public static ASN1Encodable parseBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo,
//        boolean declaredExplicit, int baseTagClass, int baseTagNo, boolean baseDeclaredExplicit) throws IOException
//    {
//        if (!taggedObjectParser.hasTag(tagClass, tagNo))
//        {
//            String expected = getTagText(tagClass, tagNo);
//            String found = getTagText(taggedObjectParser);
//            throw new ASN1Exception("Expected " + expected + " tag but found " + found);
//        }
//
//        return taggedObjectParser.parseBaseObject(declaredExplicit, baseTagClass, baseTagNo, baseDeclaredExplicit);
//    }
//
//  public static ASN1Encodable parseContextBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagNo,
//      boolean declaredExplicit, int baseTagClass, int baseTagNo, boolean baseDeclaredExplicit) throws IOException
//  {
//      return parseBaseObject(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo, declaredExplicit, baseTagClass,
//          baseTagNo, baseDeclaredExplicit);
//  }
//
//  public static ASN1Encodable tryParseBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo,
//      boolean declaredExplicit, int baseTagClass, int baseTagNo, boolean baseDeclaredExplicit) throws IOException
//  {
//      if (!taggedObjectParser.hasTag(tagClass, tagNo))
//      {
//          return null;
//      }
//
//      return taggedObjectParser.parseBaseObject(declaredExplicit, baseTagClass, baseTagNo, baseDeclaredExplicit);
//  }
//
//  public static ASN1Encodable tryParseContextBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagNo,
//      boolean declaredExplicit, int baseTagClass, int baseTagNo, boolean baseDeclaredExplicit) throws IOException
//  {
//      return tryParseBaseObject(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo, declaredExplicit, baseTagClass,
//          baseTagNo, baseDeclaredExplicit);
//  }


  /*
   * Wrappers for ASN1TaggedObjectParser#parseBaseUniversal
   */

  public static ASN1Encodable parseBaseUniversal(ASN1TaggedObjectParser taggedObjectParser,
      int tagClass,
      int tagNo, boolean declaredExplicit, int baseTagNo) throws IOException {
    if (!taggedObjectParser.hasTag(tagClass, tagNo)) {
      String expected = getTagText(tagClass, tagNo);
      String found = getTagText(taggedObjectParser);
      throw new ASN1Exception("Expected " + expected + " tag but found " + found);
    }

    return taggedObjectParser.parseBaseUniversal(declaredExplicit, baseTagNo);
  }

  public static ASN1Encodable parseContextBaseUniversal(ASN1TaggedObjectParser taggedObjectParser,
      int tagNo,
      boolean declaredExplicit, int baseTagNo) throws IOException {
    return parseBaseUniversal(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo, declaredExplicit,
        baseTagNo);
  }

  public static ASN1Encodable tryParseBaseUniversal(ASN1TaggedObjectParser taggedObjectParser,
      int tagClass,
      int tagNo, boolean declaredExplicit, int baseTagNo) throws IOException {
    if (!taggedObjectParser.hasTag(tagClass, tagNo)) {
      return null;
    }

    return taggedObjectParser.parseBaseUniversal(declaredExplicit, baseTagNo);
  }

  public static ASN1Encodable tryParseContextBaseUniversal(
      ASN1TaggedObjectParser taggedObjectParser, int tagNo,
      boolean declaredExplicit, int baseTagNo) throws IOException {
    return tryParseBaseUniversal(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo,
        declaredExplicit, baseTagNo);
  }
}