package org.ghost.media.send

/**
 * The explicit down-mix matrices of Phase 11 design §8.3 (S0-20): Media3 1.11.1's
 * `ChannelMixingMatrix.createForConstantGain(n, 2)` throws for every input count from 3 to 8, so
 * GHOST supplies its own matrix for every input count 1 … 8. Row-major `[input][output]`, two
 * output channels (stereo AAC):
 *
 *  - 5.1 (FL FR FC LFE BL BR) as ITU-R BS.775 without the LFE: front left/right at `n`, centre
 *    and both surrounds at `k·n` with `k = 1/√2` and `n = 1/(1 + 2k)`;
 *  - every other count alternates left/right at gain `2/n`.
 *
 * These are constants of `GhostTranscoder` per the design, pinned here so a unit test reads them
 * without an Android runtime. More than 8 input channels refuse the send (`CHANNELS`, §6.2).
 */
object DownMix {
    private const val K: Float = 0.7071f
    private const val N: Float = 1f / (1f + 2f * K)

    /** The matrix for [inputChannels] inputs (1 … 8), or null outside the range. */
    fun matrix(inputChannels: Int): FloatArray? {
        if (inputChannels !in 1..8) return null
        val m = FloatArray(inputChannels * 2)
        when (inputChannels) {
            1 -> {
                m[0] = 1f
                m[1] = 1f
            }
            2 -> {
                m[0] = 1f
                m[3] = 1f
            }
            6 -> {
                m[0 * 2] = N; m[1 * 2 + 1] = N
                m[2 * 2] = K * N; m[2 * 2 + 1] = K * N
                m[4 * 2] = K * N
                m[5 * 2 + 1] = K * N
            }
            else -> {
                for (i in 0 until inputChannels) m[i * 2 + (i % 2)] = 2f / inputChannels
            }
        }
        return m
    }
}
