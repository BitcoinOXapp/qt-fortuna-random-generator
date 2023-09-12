#ifndef TIMINGENTROPYSOURCE_H
#define TIMINGENTROPYSOURCE_H

#include <QTimer>
#include <QPointer>

#include "abstractentropysource.h"

class TimingEntropySource : public AbstractEntropySource
{
    Q_OBJECT
public:
    TimingEntropySource();
    void setCollectInterval(const quint32 _intervalSec);

    void startCollect() override;
    void stopCollect() override;

private:
    QPointer<QTimer> m_collectDataTimer;
};

#endif // TIMINGENTROPYSOURCE_H
