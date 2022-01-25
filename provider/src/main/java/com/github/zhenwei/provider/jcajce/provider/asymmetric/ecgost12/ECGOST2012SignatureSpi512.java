package com.github.zhenwei.provider.jcajce.provider.asymmetric.ecgost12;

import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.asn1.x509.X509ObjectIdentifiers;
import com.github.zhenwei.core.crypto.DSAExt;
import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.crypto.digests.GOST3411_2012_512Digest;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.params.ECKeyParameters;
import com.github.zhenwei.core.crypto.params.ParametersWithRandom;
import com.github.zhenwei.core.crypto.signers.ECGOST3410_2012Signer;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.util.ECUtil;
import com.github.zhenwei.provider.jce.interfaces.ECKey;
import com.github.zhenwei.provider.jce.interfaces.ECPublicKey;
import com.github.zhenwei.provider.jce.provider.LinLongProvider;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Signature for GOST34.10 2012 512. Algorithm is the same as for GOST34.10 2001
 */
public class ECGOST2012SignatureSpi512
    extends java.security.SignatureSpi
    implements PKCSObjectIdentifiers, X509ObjectIdentifiers {

  private Digest digest;
  private DSAExt signer;
  private int size = 128;
  private int halfSize = 64;


  public ECGOST2012SignatureSpi512() {
    this.digest = new GOST3411_2012_512Digest();
    this.signer = new ECGOST3410_2012Signer();
  }

  protected void engineInitVerify(
      PublicKey publicKey)
      throws InvalidKeyException {
    ECKeyParameters param;

    if (publicKey instanceof ECPublicKey) {
      param = (ECKeyParameters) generatePublicKeyParameter(publicKey);
    } else {
      try {
        byte[] bytes = publicKey.getEncoded();

        publicKey = LinLongProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(bytes));

        param = (ECKeyParameters) ECUtil.generatePublicKeyParameter(publicKey);
      } catch (Exception e) {
        throw new InvalidKeyException("cannot recognise key type in ECGOST-2012-512 signer");
      }
    }

    if (param.getParameters().getN().bitLength() < 505) {
      throw new InvalidKeyException("key too weak for ECGOST-2012-512");
    }

    digest.reset();
    signer.init(false, param);
  }

  protected void engineInitSign(
      PrivateKey privateKey)
      throws InvalidKeyException {
    ECKeyParameters param;

    if (privateKey instanceof ECKey) {
      param = (ECKeyParameters) ECUtil.generatePrivateKeyParameter(privateKey);
    } else {
      throw new InvalidKeyException("cannot recognise key type in ECGOST-2012-512 signer");
    }

    if (param.getParameters().getN().bitLength() < 505) {
      throw new InvalidKeyException("key too weak for ECGOST-2012-512");
    }

    digest.reset();

    if (appRandom != null) {
      signer.init(true, new ParametersWithRandom(param, appRandom));
    } else {
      signer.init(true, param);
    }
  }

  protected void engineUpdate(
      byte b)
      throws SignatureException {
    digest.update(b);
  }

  protected void engineUpdate(
      byte[] b,
      int off,
      int len)
      throws SignatureException {
    digest.update(b, off, len);
  }

  protected byte[] engineSign()
      throws SignatureException {
    byte[] hash = new byte[digest.getDigestSize()];

    digest.doFinal(hash, 0);

    try {
      byte[] sigBytes = new byte[size];
      BigInteger[] sig = signer.generateSignature(hash);
      byte[] r = sig[0].toByteArray();
      byte[] s = sig[1].toByteArray();

      if (s[0] != 0) {
        System.arraycopy(s, 0, sigBytes, halfSize - s.length, s.length);
      } else {
        System.arraycopy(s, 1, sigBytes, halfSize - (s.length - 1), s.length - 1);
      }

      if (r[0] != 0) {
        System.arraycopy(r, 0, sigBytes, size - r.length, r.length);
      } else {
        System.arraycopy(r, 1, sigBytes, size - (r.length - 1), r.length - 1);
      }

      return sigBytes;
    } catch (Exception e) {
      throw new SignatureException(e.toString());
    }
  }

  protected boolean engineVerify(
      byte[] sigBytes)
      throws SignatureException {
    byte[] hash = new byte[digest.getDigestSize()];

    digest.doFinal(hash, 0);

    BigInteger[] sig;

    try {
      byte[] r = new byte[halfSize];
      byte[] s = new byte[halfSize];

      System.arraycopy(sigBytes, 0, s, 0, halfSize);

      System.arraycopy(sigBytes, halfSize, r, 0, halfSize);

      sig = new BigInteger[2];
      sig[0] = new BigInteger(1, r);
      sig[1] = new BigInteger(1, s);
    } catch (Exception e) {
      throw new SignatureException("error decoding signature bytes.");
    }

    return signer.verifySignature(hash, sig[0], sig[1]);
  }

  protected void engineSetParameter(
      AlgorithmParameterSpec params) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }

  protected AlgorithmParameters engineGetParameters() {
    return null;
  }

  /**
   * @deprecated replaced with #engineSetParameter(java.security.spec.AlgorithmParameterSpec)
   */
  protected void engineSetParameter(
      String param,
      Object value) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }

  /**
   * @deprecated
   */
  protected Object engineGetParameter(
      String param) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }

  static AsymmetricKeyParameter generatePublicKeyParameter(
      PublicKey key)
      throws InvalidKeyException {
    return (key instanceof BCECGOST3410_2012PublicKey)
        ? ((BCECGOST3410_2012PublicKey) key).engineGetKeyParameters()
        : ECUtil.generatePublicKeyParameter(key);
  }
}