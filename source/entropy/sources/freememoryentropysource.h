#ifndef FREEMEMORYENTROPYSOURCE_H
#define FREEMEMORYENTROPYSOURCE_H

#include "timingentropysource.h"

class FreeMemoryEntropySource : public TimingEntropySource
{
    Q_OBJECT
public:
    FreeMemoryEntropySource();

    QByteArray getData() override;

private:
    QByteArray m_data;
};

#endif // FREEMEMORYENTROPYSOURCE_H
