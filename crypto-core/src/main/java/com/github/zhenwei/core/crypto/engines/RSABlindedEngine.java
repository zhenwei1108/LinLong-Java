package com.github.zhenwei.core.crypto.engines;

import com.github.zhenwei.core.crypto.AsymmetricBlockCipher;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.CryptoServicesRegistrar;
import com.github.zhenwei.core.crypto.DataLengthException;
import com.github.zhenwei.core.crypto.params.ParametersWithRandom;
import com.github.zhenwei.core.crypto.params.RSAKeyParameters;
import com.github.zhenwei.core.crypto.params.RSAPrivateCrtKeyParameters;
import com.github.zhenwei.core.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * this does your basic RSA algorithm with blinding
 */
public class RSABlindedEngine
    implements AsymmetricBlockCipher {

  private static final BigInteger ONE = BigInteger.valueOf(1);

  private RSACoreEngine core = new RSACoreEngine();
  private RSAKeyParameters key;
  private SecureRandom random;

  /**
   * initialise the RSA engine.
   *
   * @param forEncryption true if we are encrypting, false otherwise.
   * @param param         the necessary RSA key parameters.
   */
  public void init(
      boolean forEncryption,
      CipherParameters param) {
    core.init(forEncryption, param);

    if (param instanceof ParametersWithRandom) {
      ParametersWithRandom rParam = (ParametersWithRandom) param;

      this.key = (RSAKeyParameters) rParam.getParameters();

      if (key instanceof RSAPrivateCrtKeyParameters) {
        this.random = rParam.getRandom();
      } else {
        this.random = null;
      }
    } else {
      this.key = (RSAKeyParameters) param;

      if (key instanceof RSAPrivateCrtKeyParameters) {
        this.random = CryptoServicesRegistrar.getSecureRandom();
      } else {
        this.random = null;
      }
    }
  }

  /**
   * Return the maximum size for an input block to this engine. For RSA this is always one byte less
   * than the key size on encryption, and the same length as the key size on decryption.
   *
   * @return maximum size for an input block.
   */
  public int getInputBlockSize() {
    return core.getInputBlockSize();
  }

  /**
   * Return the maximum size for an output block to this engine. For RSA this is always one byte
   * less than the key size on decryption, and the same length as the key size on encryption.
   *
   * @return maximum size for an output block.
   */
  public int getOutputBlockSize() {
    return core.getOutputBlockSize();
  }

  /**
   * Process a single block using the basic RSA algorithm.
   *
   * @param in    the input array.
   * @param inOff the offset into the input buffer where the data starts.
   * @param inLen the length of the data to be processed.
   * @return the result of the RSA process.
   * @throws DataLengthException the input block is too large.
   */
  public byte[] processBlock(
      byte[] in,
      int inOff,
      int inLen) {
    if (key == null) {
      throw new IllegalStateException("RSA engine not initialised");
    }

    BigInteger input = core.convertInput(in, inOff, inLen);

    BigInteger result;
    if (key instanceof RSAPrivateCrtKeyParameters) {
      RSAPrivateCrtKeyParameters k = (RSAPrivateCrtKeyParameters) key;

      BigInteger e = k.getPublicExponent();
      if (e != null)   // can't do blinding without a public exponent
      {
        BigInteger m = k.getModulus();
        BigInteger r = BigIntegers.createRandomInRange(ONE, m.subtract(ONE), random);

        BigInteger blindedInput = r.modPow(e, m).multiply(input).mod(m);
        BigInteger blindedResult = core.processBlock(blindedInput);

        BigInteger rInv = BigIntegers.modOddInverse(m, r);
        result = blindedResult.multiply(rInv).mod(m);
        // defence against Arjen Lenstra’s CRT attack
        if (!input.equals(result.modPow(e, m))) {
          throw new IllegalStateException("RSA engine faulty decryption/signing detected");
        }
      } else {
        result = core.processBlock(input);
      }
    } else {
      result = core.processBlock(input);
    }

    return core.convertOutput(result);
  }
}