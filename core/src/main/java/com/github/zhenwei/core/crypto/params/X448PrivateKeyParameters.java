package com.github.zhenwei.core.crypto.params;

import com.github.zhenwei.core.math.ec.rfc7748.X448;
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.core.util.io.Streams;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;


public final class X448PrivateKeyParameters
    extends AsymmetricKeyParameter {

  public static final int KEY_SIZE = X448.SCALAR_SIZE;
  public static final int SECRET_SIZE = X448.POINT_SIZE;

  private final byte[] data = new byte[KEY_SIZE];

  public X448PrivateKeyParameters(SecureRandom random) {
    super(true);

    X448.generatePrivateKey(random, data);
  }

  public X448PrivateKeyParameters(byte[] buf) {
    this(validate(buf), 0);
  }

  public X448PrivateKeyParameters(byte[] buf, int off) {
    super(true);

    System.arraycopy(buf, off, data, 0, KEY_SIZE);
  }

  public X448PrivateKeyParameters(InputStream input) throws IOException {
    super(true);

    if (KEY_SIZE != Streams.readFully(input, data)) {
      throw new EOFException("EOF encountered in middle of X448 private key");
    }
  }

  public void encode(byte[] buf, int off) {
    System.arraycopy(data, 0, buf, off, KEY_SIZE);
  }

  public byte[] getEncoded() {
    return Arrays.clone(data);
  }

  public X448PublicKeyParameters generatePublicKey() {
    byte[] publicKey = new byte[X448.POINT_SIZE];
    X448.generatePublicKey(data, 0, publicKey, 0);
    return new X448PublicKeyParameters(publicKey, 0);
  }

  public void generateSecret(X448PublicKeyParameters publicKey, byte[] buf, int off) {
    byte[] encoded = new byte[X448.POINT_SIZE];
    publicKey.encode(encoded, 0);
    if (!X448.calculateAgreement(data, 0, encoded, 0, buf, off)) {
      throw new IllegalStateException("X448 agreement failed");
    }
  }

  private static byte[] validate(byte[] buf) {
    if (buf.length != KEY_SIZE) {
      throw new IllegalArgumentException("'buf' must have length " + KEY_SIZE);
    }
    return buf;
  }
}