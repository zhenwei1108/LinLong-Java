package com.github.zhenwei.pkix.cert.crmf.bc;

import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.crypto.digests.SHA1Digest;
import com.github.zhenwei.core.crypto.generators.MGF1BytesGenerator;
import com.github.zhenwei.core.crypto.params.MGFParameters;
import com.github.zhenwei.pkix.cert.crmf.EncryptedValuePadder;
import java.security.SecureRandom;

/**
 * An encrypted value padder that uses MGF1 as the basis of the padding.
 */
public class BcFixedLengthMGF1Padder
    implements EncryptedValuePadder {

  private int length;
  private SecureRandom random;
  private Digest dig = new SHA1Digest();

  /**
   * Create a padder to so that padded output will always be at least length bytes long.
   *
   * @param length fixed length for padded output.
   */
  public BcFixedLengthMGF1Padder(int length) {
    this(length, null);
  }

  /**
   * Create a padder to so that padded output will always be at least length bytes long, using the
   * passed in source of randomness to provide the random material for the padder.
   *
   * @param length fixed length for padded output.
   * @param random a source of randomness.
   */
  public BcFixedLengthMGF1Padder(int length, SecureRandom random) {
    this.length = length;
    this.random = random;
  }

  public byte[] getPaddedData(byte[] data) {
    byte[] bytes = new byte[length];
    byte[] seed = new byte[dig.getDigestSize()];
    byte[] mask = new byte[length - dig.getDigestSize()];

    if (random == null) {
      random = new SecureRandom();
    }

    random.nextBytes(seed);

    MGF1BytesGenerator maskGen = new MGF1BytesGenerator(dig);

    maskGen.init(new MGFParameters(seed));

    maskGen.generateBytes(mask, 0, mask.length);

    System.arraycopy(seed, 0, bytes, 0, seed.length);
    System.arraycopy(data, 0, bytes, seed.length, data.length);

    for (int i = seed.length + data.length + 1; i != bytes.length; i++) {
      bytes[i] = (byte) (1 + random.nextInt(255));
    }

    for (int i = 0; i != mask.length; i++) {
      bytes[i + seed.length] ^= mask[i];
    }

    return bytes;
  }

  public byte[] getUnpaddedData(byte[] paddedData) {
    byte[] seed = new byte[dig.getDigestSize()];
    byte[] mask = new byte[length - dig.getDigestSize()];

    System.arraycopy(paddedData, 0, seed, 0, seed.length);

    MGF1BytesGenerator maskGen = new MGF1BytesGenerator(dig);

    maskGen.init(new MGFParameters(seed));

    maskGen.generateBytes(mask, 0, mask.length);

    for (int i = 0; i != mask.length; i++) {
      paddedData[i + seed.length] ^= mask[i];
    }

    int end = 0;

    for (int i = paddedData.length - 1; i != seed.length; i--) {
      if (paddedData[i] == 0) {
        end = i;
        break;
      }
    }

    if (end == 0) {
      throw new IllegalStateException("bad padding in encoding");
    }

    byte[] data = new byte[end - seed.length];

    System.arraycopy(paddedData, seed.length, data, 0, data.length);

    return data;
  }
}