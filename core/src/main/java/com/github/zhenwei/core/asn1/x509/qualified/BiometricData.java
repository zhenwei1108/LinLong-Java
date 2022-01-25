package com.github.zhenwei.core.asn1.x509.qualified;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1IA5String;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERIA5String;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import java.util.Enumeration;

/**
 * The BiometricData object.
 * <pre>
 * BiometricData  ::=  SEQUENCE {
 *       typeOfBiometricData  TypeOfBiometricData,
 *       hashAlgorithm        AlgorithmIdentifier,
 *       biometricDataHash    OCTET STRING,
 *       sourceDataUri        IA5String OPTIONAL  }
 * </pre>
 */
public class BiometricData
    extends ASN1Object {

  private TypeOfBiometricData typeOfBiometricData;
  private AlgorithmIdentifier hashAlgorithm;
  private ASN1OctetString biometricDataHash;
  private ASN1IA5String sourceDataUri;

  public static BiometricData getInstance(
      Object obj) {
    if (obj instanceof BiometricData) {
      return (BiometricData) obj;
    }

    if (obj != null) {
      return new BiometricData(ASN1Sequence.getInstance(obj));
    }

    return null;
  }

  private BiometricData(ASN1Sequence seq) {
    Enumeration e = seq.getObjects();

    // typeOfBiometricData
    typeOfBiometricData = TypeOfBiometricData.getInstance(e.nextElement());
    // hashAlgorithm
    hashAlgorithm = AlgorithmIdentifier.getInstance(e.nextElement());
    // biometricDataHash
    biometricDataHash = ASN1OctetString.getInstance(e.nextElement());
    // sourceDataUri
    if (e.hasMoreElements()) {
      sourceDataUri = ASN1IA5String.getInstance(e.nextElement());
    }
  }

  public BiometricData(
      TypeOfBiometricData typeOfBiometricData,
      AlgorithmIdentifier hashAlgorithm,
      ASN1OctetString biometricDataHash,
      ASN1IA5String sourceDataUri) {
    this.typeOfBiometricData = typeOfBiometricData;
    this.hashAlgorithm = hashAlgorithm;
    this.biometricDataHash = biometricDataHash;
    this.sourceDataUri = sourceDataUri;
  }

  public BiometricData(
      TypeOfBiometricData typeOfBiometricData,
      AlgorithmIdentifier hashAlgorithm,
      ASN1OctetString biometricDataHash) {
    this.typeOfBiometricData = typeOfBiometricData;
    this.hashAlgorithm = hashAlgorithm;
    this.biometricDataHash = biometricDataHash;
    this.sourceDataUri = null;
  }

  public TypeOfBiometricData getTypeOfBiometricData() {
    return typeOfBiometricData;
  }

  public AlgorithmIdentifier getHashAlgorithm() {
    return hashAlgorithm;
  }

  public ASN1OctetString getBiometricDataHash() {
    return biometricDataHash;
  }

  /**
   * @deprecated Use {@link #getSourceDataUriIA5()} instead.
   */
  public DERIA5String getSourceDataUri() {
    return null == sourceDataUri || sourceDataUri instanceof DERIA5String
        ? (DERIA5String) sourceDataUri
        : new DERIA5String(sourceDataUri.getString(), false);
  }

  public ASN1IA5String getSourceDataUriIA5() {
    return sourceDataUri;
  }

  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector seq = new ASN1EncodableVector(4);
    seq.add(typeOfBiometricData);
    seq.add(hashAlgorithm);
    seq.add(biometricDataHash);

    if (sourceDataUri != null) {
      seq.add(sourceDataUri);
    }

    return new DERSequence(seq);
  }
}