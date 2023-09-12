#include "abstractentropysource.h"
#include <QDebug>

AbstractEntropySource::AbstractEntropySource(QObject* parent) :
    QObject(parent),
    m_pools(nullptr),
    m_poolIndex(0)
{
}

void AbstractEntropySource::setPools(const QSharedPointer<QVector<Pool>> _pools)
{
    if (!_pools)
        return;

    m_pools = _pools;
    emit poolsChanged();
}

void AbstractEntropySource::updatePool()
{
    if (!m_pools)
        return;

    auto sourceData { getData() };

    if (sourceData.isEmpty())
    {
        qWarning() << "Source data is empty";
        return;
    }

    m_poolIndex = ++m_poolIndex % m_pools->size();
    Pool& currentPool = (*m_pools)[m_poolIndex];
    currentPool.addData(sourceData);
}
