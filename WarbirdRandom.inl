/**
  *
  * Pseudorandom number generator
  *
  **/

namespace WarbirdRuntime
{

class CRand
{
public:
    VOID 
    Init(
        LONG    nSeed
        )
    {
        m_HoldRandom = nSeed;
    }

    SIZE_T 
    Random(
        )
    {
        return ((m_HoldRandom = m_HoldRandom * 214013L + 2531011L) >> 16) & 0xffff;
    }

    SIZE_T 
    Random(
        SIZE_T  nMin, 
        SIZE_T  nMax
        )
    {
        if (nMin > nMax)
        {
            return nMin;
        }

        SIZE_T nRange = nMax - nMin + 1;

        SIZE_T nRandom = 0;

        for (SIZE_T i = nRange; i != 0; i >>= 16)
        {
            nRandom = (nRandom << 16) | Random();
        }

        return nMin + (nRandom % nRange);
    }

private:
    SIZE_T  m_HoldRandom;

}; // class CRand

CRand g_Rand;

}; // namespace WarbirdRuntime 