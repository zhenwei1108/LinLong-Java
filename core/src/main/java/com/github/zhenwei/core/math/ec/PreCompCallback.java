package com.github.zhenwei.core.math.ec;

import org.bouncycastle.math.ec.PreCompInfo;

public interface PreCompCallback
{
    PreCompInfo precompute(PreCompInfo existing);
}