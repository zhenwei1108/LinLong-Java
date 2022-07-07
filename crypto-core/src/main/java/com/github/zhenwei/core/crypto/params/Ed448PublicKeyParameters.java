package com.github.zhenwei.core.crypto.params;

import com.github.zhenwei.core.math.ec.rfc8032.Ed448;
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.core.util.io.Streams;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public final class Ed448PublicKeyParameters
    extends AsymmetricKeyParameter {

  public static final int KEY_SIZE = Ed448.PUBLIC_KEY_SIZE;

  private final byte[] data = new byte[KEY_SIZE];

  public Ed448PublicKeyParameters(byte[] buf) {
    this(validate(buf), 0);
  }

  public Ed448PublicKeyParameters(byte[] buf, int off) {
    super(false);

    System.arraycopy(buf, off, data, 0, KEY_SIZE);
  }

  public Ed448PublicKeyParameters(InputStream input) throws IOException {
    super(false);

    if (KEY_SIZE != Streams.readFully(input, data)) {
      throw new EOFException("EOF encountered in middle of Ed448 public key");
    }
  }

  public void encode(byte[] buf, int off) {
    System.arraycopy(data, 0, buf, off, KEY_SIZE);
  }

  public byte[] getEncoded() {
    return Arrays.clone(data);
  }

  private static byte[] validate(byte[] buf) {
    if (buf.length != KEY_SIZE) {
      throw new IllegalArgumentException("'buf' must have length " + KEY_SIZE);
    }
    return buf;
  }
}