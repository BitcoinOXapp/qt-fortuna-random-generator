#ifndef DATACOLLECTOR_H
#define DATACOLLECTOR_H

#include <QVector>
#include "sources/abstractentropysource.h"
///
/// \brief The DataCollector class - Entropy collector
///
class DataCollector : public QObject
{
    Q_OBJECT
public:
    DataCollector(QObject *parent);

    QVector<AbstractEntropySource*> sources() const;

    bool hasSources() const;
    int count() const;
    AbstractEntropySource *at(int _index) const;

public slots:
    void addSource(AbstractEntropySource* _source);
    void clearSources();

private:
    QVector<AbstractEntropySource*> m_sources;

signals:
    void sourcesChanged();
};

#endif // DATACOLLECTOR_H
