// Warbird 2 used this symbol to reference all runtime elements.
// Some libs may still reference this symbol.
// This instantiation of a symbol with this name has no current purpose
// except to satisfy that requirement for linking.
extern "C" unsigned int WarbirdRuntimeRef = 0;

#ifdef WARBIRD_TEST

class CTest
{
public:
    CTest();

    void ReportVerifyFailure();

    void IncrementVerifyCount();

    ULONG GetVerifyCount();

    void ResetVerifyCount();

private:
    ULONG   m_nVerifyCount;
};

CTest::CTest()
{
    m_nVerifyCount = 0;
}

void CTest::ReportVerifyFailure()
{
    __debugbreak();
    return;
}

void CTest::IncrementVerifyCount()
{
    m_nVerifyCount++;
}

ULONG CTest::GetVerifyCount()
{
    return m_nVerifyCount;
}

void CTest::ResetVerifyCount()
{
    m_nVerifyCount = 0;
}

extern CTest* g_pTestClass;

#endif