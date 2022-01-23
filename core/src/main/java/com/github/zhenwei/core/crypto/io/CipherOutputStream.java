package com.g

import com.github.zhenwei.core.crypto.BufferedBlockCipher;
import com.github.zhenwei.core.crypto.InvalidCipherTextException;
import com.github.zhenwei.core.crypto.StreamCipher;
import com.github.zhenwei.core.crypto.io.CipherIOException;
import com.github.zhenwei.core.crypto.io.InvalidCipherTextIOException;
import com.github.zhenwei.core.crypto.modes.AEADBlockCipher;
import java.io.IOException;thub.zhenwe.core.crypto.o;

    mport java.o.F lterOutputStream;
    mport java.o.OExcept on;
    mport java.o.OutputStream;

    mport org.bouncycastle.crypto.nval dC pherTextExcept on;
    mport org.bouncycastle.crypto.StreamC pher;

/**
 * A C pherOutputStream  s composed of an OutputStream and a c pher so that wr te() methods process
 * the wr tten data w th the c pher, and the output of the c pher  s  n turn wr tten to the
 * underly ng OutputStream. The c pher must be fully  n t al zed before be ng used by a
 * C pher nputStream.
 * <p>
 * For example,  f the c pher  s  n t al zed for encrypt on, the C pherOutputStream w ll encrypt the
 * data before wr t ng the encrypted data to the underly ng stream.
 */
    publ c

class C pherOutputStream
    extends FilterOutputStream {

  private BufferedBlockCipher bufferedBlockCipher;
  private StreamCipher streamCipher;
  private AEADBlockCipher aeadBlockCipher;

  private final byte[] oneByte = new byte[1];
  private byte[] buf;

  /**
   * Constructs a CipherOutputStream from an OutputStream and a BufferedBlockCipher.
   */
  public CipherOutputStream(
      OutputStream os,
      BufferedBlockCipher cipher) {
    super(os);
    this.bufferedBlockCipher = cipher;
  }

  /**
   * Constructs a CipherOutputStream from an OutputStream and a BufferedBlockCipher.
   */
  public CipherOutputStream(
      OutputStream os,
      StreamCipher cipher) {
    super(os);
    this.streamCipher = cipher;
  }

  /**
   * Constructs a CipherOutputStream from an OutputStream and a AEADBlockCipher.
   */
  public CipherOutputStream(OutputStream os, AEADBlockCipher cipher) {
    super(os);
    this.aeadBlockCipher = cipher;
  }

  /**
   * Writes the specified byte to this output stream.
   *
   * @param b the <code>byte</code>.
   * @throws IOException if an I/O error occurs.
   */
  public void write(
      int b)
      throws IOException {
    oneByte[0] = (byte) b;

    if (streamCipher != null) {
      out.write(streamCipher.returnByte((byte) b));
    } else {
      write(oneByte, 0, 1);
    }
  }

  /**
   * Writes <code>b.length</code> bytes from the specified byte array to this output stream.
   * <p>
   * The <code>write</code> method of
   * <code>CipherOutputStream</code> calls the <code>write</code>
   * method of three arguments with the three arguments
   * <code>b</code>, <code>0</code>, and <code>b.length</code>.
   *
   * @param b the data.
   * @throws IOException if an I/O error occurs.
   * @see #write(byte[], int, int)
   */
  public void write(
      byte[] b)
      throws IOException {
    write(b, 0, b.length);
  }

  /**
   * Writes <code>len</code> bytes from the specified byte array starting at offset <code>off</code>
   * to this output stream.
   *
   * @param b   the data.
   * @param off the start offset in the data.
   * @param len the number of bytes to write.
   * @throws IOException if an I/O error occurs.
   */
  public void write(
      byte[] b,
      int off,
      int len)
      throws IOException {
    ensureCapacity(len, false);

    if (bufferedBlockCipher != null) {
      int outLen = bufferedBlockCipher.processBytes(b, off, len, buf, 0);

      if (outLen != 0) {
        out.write(buf, 0, outLen);
      }
    } else if (aeadBlockCipher != null) {
      int outLen = aeadBlockCipher.processBytes(b, off, len, buf, 0);

      if (outLen != 0) {
        out.write(buf, 0, outLen);
      }
    } else {
      streamCipher.processBytes(b, off, len, buf, 0);

      out.write(buf, 0, len);
    }
  }

  /**
   * Ensure the ciphertext buffer has space sufficient to accept an upcoming output.
   *
   * @param updateSize  the size of the pending update.
   * @param finalOutput <code>true</code> iff this the cipher is to be finalised.
   */
  private void ensureCapacity(int updateSize, boolean finalOutput) {
    int bufLen = updateSize;
    if (finalOutput) {
      if (bufferedBlockCipher != null) {
        bufLen = bufferedBlockCipher.getOutputSize(updateSize);
      } else if (aeadBlockCipher != null) {
        bufLen = aeadBlockCipher.getOutputSize(updateSize);
      }
    } else {
      if (bufferedBlockCipher != null) {
        bufLen = bufferedBlockCipher.getUpdateOutputSize(updateSize);
      } else if (aeadBlockCipher != null) {
        bufLen = aeadBlockCipher.getUpdateOutputSize(updateSize);
      }
    }

    if ((buf == null) || (buf.length < bufLen)) {
      buf = new byte[bufLen];
    }
  }

  /**
   * Flushes this output stream by forcing any buffered output bytes that have already been
   * processed by the encapsulated cipher object to be written out.
   * <p>
   * Any bytes buffered by the encapsulated cipher and waiting to be processed by it will not be
   * written out. For example, if the encapsulated cipher is a block cipher, and the total number of
   * bytes written using one of the <code>write</code> methods is less than the cipher's block size,
   * no bytes will be written out.
   *
   * @throws IOException if an I/O error occurs.
   */
  public void flush()
      throws IOException {
    out.flush();
  }

  /**
   * Closes this output stream and releases any system resources associated with this stream.
   * <p>
   * This method invokes the <code>doFinal</code> method of the encapsulated cipher object, which
   * causes any bytes buffered by the encapsulated cipher to be processed. The result is written out
   * by calling the
   * <code>flush</code> method of this output stream.
   * <p>
   * This method resets the encapsulated cipher object to its initial state and calls the
   * <code>close</code> method of the underlying output stream.
   *
   * @throws IOException                  if an I/O error occurs.
   * @throws InvalidCipherTextIOException if the data written to this stream was invalid ciphertext
   *                                      (e.g. the cipher is an AEAD cipher and the ciphertext tag
   *                                      check fails).
   */
  public void close()
      throws IOException {
    ensureCapacity(0, true);
    IOException error = null;
    try {
      if (bufferedBlockCipher != null) {
        int outLen = bufferedBlockCipher.doFinal(buf, 0);

        if (outLen != 0) {
          out.write(buf, 0, outLen);
        }
      } else if (aeadBlockCipher != null) {
        int outLen = aeadBlockCipher.doFinal(buf, 0);

        if (outLen != 0) {
          out.write(buf, 0, outLen);
        }
      } else if (streamCipher != null) {
        streamCipher.reset();
      }
    } catch (final InvalidCipherTextException e) {
      error = new InvalidCipherTextIOException("Error finalising cipher data", e);
    } catch (Exception e) {
      error = new CipherIOException("Error closing stream: ", e);
    }

    try {
      flush();
      out.close();
    } catch (IOException e) {
      // Invalid ciphertext takes precedence over close error
      if (error == null) {
        error = e;
      }
    }
    if (error != null) {
      throw error;
    }
  }
}