#include "datacollector.h"
#include <QDebug>

DataCollector::DataCollector(QObject *parent) :
    QObject(parent),
    m_sources({})
{
}

bool DataCollector::hasSources() const
{
    return m_sources.size() != 0;
}

int DataCollector::count() const
{
    return m_sources.count();
}

AbstractEntropySource *DataCollector::at(int _index) const
{
    return m_sources.at(_index);
}

//void DataCollector::addSource(const QSharedPointer<AbstractEntropySource> &_source)
//{
//    if (!_source)
//        return;

//    m_sources.push_back(_source.data());
//    _source->startCollect();
//}

void DataCollector::addSource(AbstractEntropySource *_source)
{
    if (!_source)
        return;

    m_sources.push_back(_source);
    _source->startCollect();
    emit sourcesChanged();
    qDebug() << "New source started to collect: " << _source->name();
}

QVector<AbstractEntropySource *> DataCollector::sources() const
{
    return m_sources;
}

void DataCollector::clearSources()
{
    for (const auto& source : qAsConst(m_sources))
    {
        if (source)
            source->stopCollect();
    }
    m_sources.clear();
    emit sourcesChanged();

    qDebug() << "All entropy sources cleaned";
}
