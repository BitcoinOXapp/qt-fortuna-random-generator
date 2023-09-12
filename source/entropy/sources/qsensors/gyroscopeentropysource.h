#ifndef GYROSCOPEENTROPYSOURCE_H
#define GYROSCOPEENTROPYSOURCE_H

#include <QGyroscope>
#include <QSharedPointer>

#include "qsensorentropysource.h"

class GyroscopeEntropySource : public QSensorEntropySource
{
public:
    GyroscopeEntropySource(QObject* parent = nullptr);

    QByteArray getData() override;
    QString name() override;

    QSharedPointer<QGyroscope> gyroscope();
};

#endif // GYROSCOPEENTROPYSOURCE_H
