package com.github.zhenwei.core.crypto.digests;

import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.util.Arrays;
import java.io.ByteArrayOutputStream;


public class NullDigest
    implements Digest {

  private OpenByteArrayOutputStream bOut = new OpenByteArrayOutputStream();

  public String getAlgorithmName() {
    return "NULL";
  }

  public int getDigestSize() {
    return bOut.size();
  }

  public void update(byte in) {
    bOut.write(in);
  }

  public void update(byte[] in, int inOff, int len) {
    bOut.write(in, inOff, len);
  }

  public int doFinal(byte[] out, int outOff) {
    int size = bOut.size();

    bOut.copy(out, outOff);

    reset();

    return size;
  }

  public void reset() {
    bOut.reset();
  }

  private static class OpenByteArrayOutputStream
      extends ByteArrayOutputStream {

    public void reset() {
      super.reset();

      Arrays.clear(buf);
    }

    void copy(byte[] out, int outOff) {
      System.arraycopy(buf, 0, out, outOff, this.size());
    }
  }
}