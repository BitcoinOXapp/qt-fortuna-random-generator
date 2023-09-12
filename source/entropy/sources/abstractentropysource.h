#ifndef ABSTRACTENTROPYSOURCE_H
#define ABSTRACTENTROPYSOURCE_H

#include <QSharedPointer>
#include <QVector>

#include "../pool.h"

class AbstractEntropySource : public QObject
{
    Q_OBJECT
public:
    AbstractEntropySource(QObject* parent = nullptr);
    void setPools(const QSharedPointer<QVector<Pool>> _pools);
    void updatePool();

    virtual QByteArray getData() = 0;
    virtual void startCollect() = 0;
    virtual void stopCollect() = 0;

    virtual QString name() = 0;

private:
    QSharedPointer<QVector<Pool>> m_pools;
    quint32 m_poolIndex;

signals:
    void poolsChanged();
};

#endif // ABSTRACTENTROPYSOURCE_H
