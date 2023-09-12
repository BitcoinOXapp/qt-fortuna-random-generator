#include "freememoryentropysource.h"

FreeMemoryEntropySource::FreeMemoryEntropySource() :
    m_data({})
{
    /// Test input data
    m_data.append(1);
    m_data.append(2);
    m_data.append(3);
    m_data.append(4);
    m_data.append(5);
}

QByteArray FreeMemoryEntropySource::getData()
{
    /// Test input data
    for (int i = 0; i < m_data.size(); ++i)
        m_data[i] = m_data[i] + 1;

    return m_data;
}
