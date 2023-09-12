#ifndef ACCELEROMETERENTROPYSOURCE_H
#define ACCELEROMETERENTROPYSOURCE_H

#include <QAccelerometer>
#include <QSharedPointer>

#include "qsensorentropysource.h"

class AccelerometerEntropySource : public QSensorEntropySource
{
public:
    AccelerometerEntropySource(QObject* parent = nullptr);

    QByteArray getData() override;
    QString name() override;

    QSharedPointer<QAccelerometer> accelerometer();
};

#endif // ACCELEROMETERENTROPYSOURCE_H
