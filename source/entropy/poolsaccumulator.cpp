#include "poolsaccumulator.h"
#include "sources/qsensors/accelerometerentropysource.h"
#include "sources/qsensors/compassentropysource.h"
#include "sources/qsensors/gyroscopeentropysource.h"
#include "sources/qsensors/lightentropysource.h"

#include <QDebug>
#include <QtQml>

PoolsAccumulator::PoolsAccumulator() :
    m_pools(new Pools(GlobalConstants::ENTROPY_POOL_COUNT))
{
    m_dataCollector = new DataCollector(nullptr);
    m_dataCollector->moveToThread(&m_collectionThread);

    connect(this, &PoolsAccumulator::s_addSource, m_dataCollector.data(), &DataCollector::addSource, Qt::QueuedConnection);
    connect(this, &PoolsAccumulator::s_clearSources, m_dataCollector.data(), &DataCollector::clearSources, Qt::QueuedConnection);
    connect(m_dataCollector.data(), &DataCollector::sourcesChanged, this, &PoolsAccumulator::sourcesChanged,  Qt::DirectConnection);
    m_collectionThread.start();
}

PoolsAccumulator::~PoolsAccumulator()
{
    qDebug() << "Accumulator stop";
    m_collectionThread.quit();
    m_collectionThread.wait();
}

void PoolsAccumulator::registerSources(const char* uri)
{
    qmlRegisterType<AccelerometerEntropySource>(uri, 1, 0, "AccelerometerEntropySource");
    qmlRegisterType<CompassEntropySource>(uri, 1, 0, "CompassEntropySource");
    qmlRegisterType<GyroscopeEntropySource>(uri, 1, 0, "GyroscopeEntropySource");
    qmlRegisterType<LightEntropySource>(uri, 1, 0, "LightEntropySource");
}

QSharedPointer<Pools> PoolsAccumulator::pools() const
{
    return m_pools;
}

void PoolsAccumulator::addSource(const QSharedPointer<AbstractEntropySource> &_source)
{
    qDebug() << "Adding smart pointer not work";
    Q_UNUSED(_source)
//    _source->setPools(m_pools);
//    _source->moveToThread(&m_collectionThread);
//    emit s_addSource(_source);
}

void PoolsAccumulator::addSource(AbstractEntropySource* _source)
{
    qDebug() << "Add new source";
    _source->setPools(m_pools);
    emit s_addSource(_source);
}

void PoolsAccumulator::addSource(const QSharedPointer<QSensor>& _sensor)
{
    addSource(_sensor->type());
}

void PoolsAccumulator::addSource(const QByteArray& _type)
{
    AbstractEntropySource* currentSource;
    if (_type == QAccelerometer::type)
    {
        currentSource = new AccelerometerEntropySource;
    }
    else if (_type == QCompass::type)
    {
        currentSource = new CompassEntropySource;
    }
    else if (_type == QGyroscope::type)
    {
        currentSource = new GyroscopeEntropySource;
    }
    else if (_type == QLightSensor::type)
    {
        currentSource = new LightEntropySource;
    }
//    QSharedPointer<AbstractEntropySource> currentSource;
//    if (_type == QAccelerometer::type)
//    {
//        currentSource = QSharedPointer<AccelerometerEntropySource>(new AccelerometerEntropySource);
//    }
//    else if (_type == QCompass::type)
//    {
//        currentSource = QSharedPointer<CompassEntropySource>(new CompassEntropySource);
//    }
//    else if (_type == QGyroscope::type)
//    {
//        currentSource = QSharedPointer<GyroscopeEntropySource>(new GyroscopeEntropySource);
//    }
//    else if (_type == QLightSensor::type)
//    {
//        currentSource = QSharedPointer<LightEntropySource>(new LightEntropySource);
//    }
    /// ...
    else
    {
        qWarning() << "Unknown sensor: " << _type;
        return;
    }

    addSource(currentSource);
}

QString PoolsAccumulator::sourcesStr() const
{
    if (!m_dataCollector)
        return {};

    QStringList resultStr;
    const auto sources { m_dataCollector->sources() };
    for (const auto& source : sources)
    {
        if (source)
            resultStr << source->name();
    }
    return resultStr.join(", ");
}

int PoolsAccumulator::sourcesCount()
{
    if (!m_dataCollector)
        return 0;

    return m_dataCollector->count();
}

AbstractEntropySource* PoolsAccumulator::at(int _index)
{
    if (!m_dataCollector)
        return nullptr;

    return m_dataCollector->at(_index);
}

void PoolsAccumulator::clearSources()
{
    emit s_clearSources();
    m_pools.clear();
}

bool PoolsAccumulator::hasEntropySource() const
{
    if (!m_dataCollector)
        return false;

    return m_dataCollector->hasSources();
}
