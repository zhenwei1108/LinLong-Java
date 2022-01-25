package com.github.zhenwei.provider.jcajce.provider.asymmetric.rsa;

import com.github.zhenwei.core.crypto.AsymmetricBlockCipher;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.crypto.digests.RIPEMD160Digest;
import com.github.zhenwei.core.crypto.digests.WhirlpoolDigest;
import com.github.zhenwei.core.crypto.engines.RSABlindedEngine;
import com.github.zhenwei.core.crypto.signers.ISO9796d2Signer;
import com.github.zhenwei.core.crypto.util.DigestFactory;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

public class ISOSignatureSpi
    extends SignatureSpi {

  private ISO9796d2Signer signer;

  protected ISOSignatureSpi(
      Digest digest,
      AsymmetricBlockCipher cipher) {
    signer = new ISO9796d2Signer(cipher, digest, true);
  }

  protected void engineInitVerify(
      PublicKey publicKey)
      throws InvalidKeyException {
    CipherParameters param = RSAUtil.generatePublicKeyParameter((RSAPublicKey) publicKey);

    signer.init(false, param);
  }

  protected void engineInitSign(
      PrivateKey privateKey)
      throws InvalidKeyException {
    CipherParameters param = RSAUtil.generatePrivateKeyParameter((RSAPrivateKey) privateKey);

    signer.init(true, param);
  }

  protected void engineUpdate(
      byte b)
      throws SignatureException {
    signer.update(b);
  }

  protected void engineUpdate(
      byte[] b,
      int off,
      int len)
      throws SignatureException {
    signer.update(b, off, len);
  }

  protected byte[] engineSign()
      throws SignatureException {
    try {
      byte[] sig = signer.generateSignature();

      return sig;
    } catch (Exception e) {
      throw new SignatureException(e.toString());
    }
  }

  protected boolean engineVerify(
      byte[] sigBytes)
      throws SignatureException {
    boolean yes = signer.verifySignature(sigBytes);

    return yes;
  }

  protected void engineSetParameter(
      AlgorithmParameterSpec params) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }

  /**
   * @deprecated replaced with <a href="#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">engineSetParameter(java.security.spec.AlgorithmParameterSpec)</a>
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

  static public class SHA1WithRSAEncryption
      extends ISOSignatureSpi {

    public SHA1WithRSAEncryption() {
      super(DigestFactory.createSHA1(), new RSABlindedEngine());
    }
  }

  static public class MD5WithRSAEncryption
      extends ISOSignatureSpi {

    public MD5WithRSAEncryption() {
      super(DigestFactory.createMD5(), new RSABlindedEngine());
    }
  }

  static public class RIPEMD160WithRSAEncryption
      extends ISOSignatureSpi {

    public RIPEMD160WithRSAEncryption() {
      super(new RIPEMD160Digest(), new RSABlindedEngine());
    }
  }

  static public class SHA224WithRSAEncryption
      extends ISOSignatureSpi {

    public SHA224WithRSAEncryption() {
      super(DigestFactory.createSHA224(), new RSABlindedEngine());
    }
  }

  static public class SHA256WithRSAEncryption
      extends ISOSignatureSpi {

    public SHA256WithRSAEncryption() {
      super(DigestFactory.createSHA256(), new RSABlindedEngine());
    }
  }

  static public class SHA384WithRSAEncryption
      extends ISOSignatureSpi {

    public SHA384WithRSAEncryption() {
      super(DigestFactory.createSHA384(), new RSABlindedEngine());
    }
  }

  static public class SHA512WithRSAEncryption
      extends ISOSignatureSpi {

    public SHA512WithRSAEncryption() {
      super(DigestFactory.createSHA512(), new RSABlindedEngine());
    }
  }

  static public class SHA512_224WithRSAEncryption
      extends ISOSignatureSpi {

    public SHA512_224WithRSAEncryption() {
      super(DigestFactory.createSHA512_224(), new RSABlindedEngine());
    }
  }

  static public class SHA512_256WithRSAEncryption
      extends ISOSignatureSpi {

    public SHA512_256WithRSAEncryption() {
      super(DigestFactory.createSHA512_256(), new RSABlindedEngine());
    }
  }

  static public class WhirlpoolWithRSAEncryption
      extends ISOSignatureSpi {

    public WhirlpoolWithRSAEncryption() {
      super(new WhirlpoolDigest(), new RSABlindedEngine());
    }
  }
}