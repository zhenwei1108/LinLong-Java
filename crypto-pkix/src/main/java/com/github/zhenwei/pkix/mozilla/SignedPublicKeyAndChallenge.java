package com.github.zhenwei.pkix.mozilla;

import com.github.zhenwei.core.asn1.ASN1BitString;
import com.github.zhenwei.core.asn1.ASN1Encoding;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.DERBitString;
import com.github.zhenwei.core.asn1.mozilla.PublicKeyAndChallenge;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.util.Encodable;
import com.github.zhenwei.pkix.operator.ContentVerifier;
import com.github.zhenwei.pkix.operator.ContentVerifierProvider;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;

/**
 * This is designed to parse the SignedPublicKeyAndChallenge created by the KEYGEN tag included by
 * Mozilla based browsers.
 * <pre>
 *  PublicKeyAndChallenge ::= SEQUENCE {
 *    spki SubjectPublicKeyInfo,
 *    challenge IA5STRING
 *  }
 *
 *  SignedPublicKeyAndChallenge ::= SEQUENCE {
 *    publicKeyAndChallenge PublicKeyAndChallenge,
 *    signatureAlgorithm AlgorithmIdentifier,
 *    signature BIT STRING
 *  }
 *  </pre>
 */
public class SignedPublicKeyAndChallenge
    implements Encodable {

  protected final com.github.zhenwei.core.asn1.mozilla.SignedPublicKeyAndChallenge spkacSeq;

  public SignedPublicKeyAndChallenge(byte[] bytes) {
    spkacSeq = com.github.zhenwei.core.asn1.mozilla.SignedPublicKeyAndChallenge.getInstance(bytes);
  }

  protected SignedPublicKeyAndChallenge(
      com.github.zhenwei.core.asn1.mozilla.SignedPublicKeyAndChallenge struct) {
    this.spkacSeq = struct;
  }

  /**
   * Return the underlying ASN.1 structure for this challenge.
   *
   * @return a SignedPublicKeyAndChallenge object.
   */
  public com.github.zhenwei.core.asn1.mozilla.SignedPublicKeyAndChallenge toASN1Structure() {
    return spkacSeq;
  }

  /**
   * @deprecated use toASN1Structure
   */
  public ASN1Primitive toASN1Primitive() {
    return spkacSeq.toASN1Primitive();
  }

  public PublicKeyAndChallenge getPublicKeyAndChallenge() {
    return spkacSeq.getPublicKeyAndChallenge();
  }

  public boolean isSignatureValid(ContentVerifierProvider verifierProvider)
      throws OperatorCreationException, IOException {
    ContentVerifier verifier = verifierProvider.get(spkacSeq.getSignatureAlgorithm());

    OutputStream sOut = verifier.getOutputStream();
    spkacSeq.getPublicKeyAndChallenge().encodeTo(sOut, ASN1Encoding.DER);
    sOut.close();

    return verifier.verify(spkacSeq.getSignature().getOctets());
  }

  /**
   * @deprecated use ContentVerifierProvider method
   */
  public boolean verify()
      throws NoSuchAlgorithmException, SignatureException,
      NoSuchProviderException, InvalidKeyException {
    return verify((String) null);
  }

  /**
   * @deprecated use ContentVerifierProvider method
   */
  public boolean verify(String provider)
      throws NoSuchAlgorithmException, SignatureException,
      NoSuchProviderException, InvalidKeyException {
    Signature sig = null;
    if (provider == null) {
      sig = Signature.getInstance(spkacSeq.getSignatureAlgorithm().getAlgorithm().getId());
    } else {
      sig = Signature.getInstance(spkacSeq.getSignatureAlgorithm().getAlgorithm().getId(),
          provider);
    }
    PublicKey pubKey = this.getPublicKey(provider);
    sig.initVerify(pubKey);
    try {
      sig.update(spkacSeq.getPublicKeyAndChallenge().getEncoded());

      return sig.verify(spkacSeq.getSignature().getBytes());
    } catch (Exception e) {
      throw new InvalidKeyException("error encoding public key");
    }
  }

  public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
    return spkacSeq.getPublicKeyAndChallenge().getSubjectPublicKeyInfo();
  }

  public String getChallenge() {
    return spkacSeq.getPublicKeyAndChallenge().getChallenge().getString();
  }

  /**
   * @deprecated use JcaSignedPublicKeyAndChallenge.getPublicKey()
   */
  public PublicKey getPublicKey(String provider)
      throws NoSuchAlgorithmException, NoSuchProviderException,
      InvalidKeyException {
    SubjectPublicKeyInfo subjectPKInfo = spkacSeq.getPublicKeyAndChallenge()
        .getSubjectPublicKeyInfo();
    try {
      ASN1BitString bStr = new DERBitString(subjectPKInfo);
      X509EncodedKeySpec xspec = new X509EncodedKeySpec(bStr.getOctets());

      AlgorithmIdentifier keyAlg = subjectPKInfo.getAlgorithm();

      KeyFactory factory =
          KeyFactory.getInstance(keyAlg.getAlgorithm().getId(), provider);

      return factory.generatePublic(xspec);

    } catch (Exception e) {
      throw new InvalidKeyException("error encoding public key");
    }
  }

  public byte[] getEncoded()
      throws IOException {
    return toASN1Structure().getEncoded();
  }
}