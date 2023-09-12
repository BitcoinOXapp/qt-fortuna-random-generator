#include "timingentropysource.h"

TimingEntropySource::TimingEntropySource() :
    m_collectDataTimer(new QTimer(this))
{
    connect(m_collectDataTimer.data(), &QTimer::timeout, this, &AbstractEntropySource::updatePool);
    m_collectDataTimer->setInterval(50);
}

void TimingEntropySource::setCollectInterval(const quint32 _intervalSec)
{
    if (!m_collectDataTimer)
        return;

    m_collectDataTimer->setInterval(_intervalSec);
}

void TimingEntropySource::startCollect()
{
    if (!m_collectDataTimer->isActive())
        m_collectDataTimer->start();
}

void TimingEntropySource::stopCollect()
{
    if (m_collectDataTimer->isActive())
        m_collectDataTimer->stop();
}
