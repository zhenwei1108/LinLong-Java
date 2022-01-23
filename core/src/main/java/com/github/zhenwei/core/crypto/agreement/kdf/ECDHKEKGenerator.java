package com.github.zhenwei.core.crypto.agreement.kdf;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Encoding;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.DERNull;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERTaggedObject;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.DataLengthException;
import com.github.zhenwei.core.crypto.DerivationParameters;
import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.crypto.DigestDerivationFunction;
import com.github.zhenwei.core.crypto.generators.KDF2BytesGenerator;
import com.github.zhenwei.core.crypto.params.KDFParameters;
import java.io.IOException;


/**
 * 63 based key derivation function for ECDH CMS.
 */
public class ECDHKEKGenerator
    implements DigestDerivationFunction {

  private DigestDerivationFunction kdf;

  private ASN1ObjectIdentifier algorithm;
  private int keySize;
  private byte[] z;

  public ECDHKEKGenerator(
      Digest digest) {
    this.kdf = new KDF2BytesGenerator(digest);
  }

  public void init(DerivationParameters param) {
    DHKDFParameters params = (DHKDFParameters) param;

    this.algorithm = params.getAlgorithm();
    this.keySize = params.getKeySize();
    this.z = params.getZ();
  }

  public Digest getDigest() {
    return kdf.getDigest();
  }

  public int generateBytes(byte[] out, int outOff, int len)
      throws DataLengthException, IllegalArgumentException {
    if (outOff + len > out.length) {
      throw new DataLengthException("output buffer too small");
    }

    // TODO Create an ASN.1 class for this (RFC3278)
    // ECC-CMS-SharedInfo
    ASN1EncodableVector v = new ASN1EncodableVector();

    v.add(new AlgorithmIdentifier(algorithm, DERNull.INSTANCE));
    v.add(new DERTaggedObject(true, 2, new DEROctetString(Pack.intToBigEndian(keySize))));

    try {
      kdf.init(new KDFParameters(z, new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    } catch (IOException e) {
      throw new IllegalArgumentException("unable to initialise kdf: " + e.getMessage());
    }

    return kdf.generateBytes(out, outOff, len);
  }
}