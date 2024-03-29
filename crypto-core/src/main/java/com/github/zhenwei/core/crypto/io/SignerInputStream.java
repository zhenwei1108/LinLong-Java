package com.github.zhenwei.core.crypto.io;

import com.github.zhenwei.core.crypto.Signer;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class SignerInputStream
    extends FilterInputStream {

  protected Signer signer;

  public SignerInputStream(
      InputStream stream,
      Signer signer) {
    super(stream);
    this.signer = signer;
  }

  public int read()
      throws IOException {
    int b = in.read();

    if (b >= 0) {
      signer.update((byte) b);
    }
    return b;
  }

  public int read(
      byte[] b,
      int off,
      int len)
      throws IOException {
    int n = in.read(b, off, len);
    if (n > 0) {
      signer.update(b, off, n);
    }
    return n;
  }

  public Signer getSigner() {
    return signer;
  }
}