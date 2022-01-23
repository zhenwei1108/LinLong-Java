package com.github.zhenwei.core.crypto.signers;

import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.DSA;
import com.github.zhenwei.core.crypto.DSAExt;
import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.crypto.Signer;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.params.ParametersWithRandom;
import java.math.BigInteger;


public class DSADigestSigner
    implements Signer {

  private final DSA dsa;
  private final Digest digest;
  private final DSAEncoding encoding;
  private boolean forSigning;

  public DSADigestSigner(
      DSA dsa,
      Digest digest) {
    this.dsa = dsa;
    this.digest = digest;
    this.encoding = StandardDSAEncoding.INSTANCE;
  }

  public DSADigestSigner(
      DSAExt dsa,
      Digest digest,
      DSAEncoding encoding) {
    this.dsa = dsa;
    this.digest = digest;
    this.encoding = encoding;
  }

  public void init(
      boolean forSigning,
      CipherParameters parameters) {
    this.forSigning = forSigning;

    AsymmetricKeyParameter k;

    if (parameters instanceof ParametersWithRandom) {
      k = (AsymmetricKeyParameter) ((ParametersWithRandom) parameters).getParameters();
    } else {
      k = (AsymmetricKeyParameter) parameters;
    }

    if (forSigning && !k.isPrivate()) {
      throw new IllegalArgumentException("Signing Requires Private Key.");
    }

    if (!forSigning && k.isPrivate()) {
      throw new IllegalArgumentException("Verification Requires Public Key.");
    }

    reset();

    dsa.init(forSigning, parameters);
  }

  /**
   * update the internal digest with the byte b
   */
  public void update(
      byte input) {
    digest.update(input);
  }

  /**
   * update the internal digest with the byte array in
   */
  public void update(
      byte[] input,
      int inOff,
      int length) {
    digest.update(input, inOff, length);
  }

  /**
   * Generate a signature for the message we've been loaded with using the key we were initialised
   * with.
   */
  public byte[] generateSignature() {
    if (!forSigning) {
      throw new IllegalStateException("DSADigestSigner not initialised for signature generation.");
    }

    byte[] hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);

    BigInteger[] sig = dsa.generateSignature(hash);

    try {
      return encoding.encode(getOrder(), sig[0], sig[1]);
    } catch (Exception e) {
      throw new IllegalStateException("unable to encode signature");
    }
  }

  public boolean verifySignature(
      byte[] signature) {
    if (forSigning) {
      throw new IllegalStateException("DSADigestSigner not initialised for verification");
    }

    byte[] hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);

    try {
      BigInteger[] sig = encoding.decode(getOrder(), signature);

      return dsa.verifySignature(hash, sig[0], sig[1]);
    } catch (Exception e) {
      return false;
    }
  }

  public void reset() {
    digest.reset();
  }

  protected BigInteger getOrder() {
    return dsa instanceof DSAExt ? ((DSAExt) dsa).getOrder() : null;
  }
}