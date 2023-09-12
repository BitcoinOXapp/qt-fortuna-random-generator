#ifndef POOLSACCUMULATOR_H
#define POOLSACCUMULATOR_H

#include <QVector>
#include <QPointer>
#include <QThread>
#include <QSharedPointer>
#include <QSensor>

#include "sources/abstractentropysource.h"
#include "datacollector.h"
#include "../globaldefs.h"

class PoolsAccumulator : public QObject
{
    Q_OBJECT
public:
    PoolsAccumulator();
    ~PoolsAccumulator();

    static void registerSources(const char* uri);

    /// getters
    QSharedPointer<Pools> pools() const;

    /// sources
    void addSource(AbstractEntropySource* _source);
    void addSource(const QByteArray& _type);
    /// TODO ?
    void addSource(const QSharedPointer<AbstractEntropySource>& _source);
    void addSource(const QSharedPointer<QSensor>& _sensor);

    QString sourcesStr() const;
    int sourcesCount();
    AbstractEntropySource* at(int _index);
    void clearSources();

    bool hasEntropySource() const;

private:
    QSharedPointer<Pools> m_pools;

    QPointer<DataCollector> m_dataCollector;
    QThread m_collectionThread;

signals:
    void s_addSource(AbstractEntropySource* _source);
    void s_clearSources();
    void sourcesChanged();
};

#endif // POOLSACCUMULATOR_H
