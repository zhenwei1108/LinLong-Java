package com.github.zhenwei.core.crypto.engines;

import com.github.zhenwei.core.util.Memoable;

/**
 * Zuc256 implementation. Based on https://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180126529970733243.pdf
 */
public final class Zuc128Engine
    extends Zuc128CoreEngine {

  /**
   * Constructor for streamCipher.
   */
  public Zuc128Engine() {
    super();
  }

  /**
   * Constructor for Memoable.
   *
   * @param pSource the source engine
   */
  private Zuc128Engine(final org.bouncycastle.crypto.engines.Zuc128Engine pSource) {
    super(pSource);
  }

  /**
   * Create a copy of the engine.
   *
   * @return the copy
   */
  public Memoable copy() {
    return new org.bouncycastle.crypto.engines.Zuc128Engine(this);
  }
}