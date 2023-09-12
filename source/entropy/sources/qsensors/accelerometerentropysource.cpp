#include <QDebug>

#include "accelerometerentropysource.h"

AccelerometerEntropySource::AccelerometerEntropySource(QObject* parent)
    : QSensorEntropySource(parent)
{
    qDebug() << "Initialize accelerometer >>>>";
    QSharedPointer<QAccelerometer> sensor(new QAccelerometer);
    initSensor(sensor);

    if (accelerometer())
        qDebug() << "Accelerometer init OK";
    else
        qDebug() << "Error accelerometer init";
}

QByteArray AccelerometerEntropySource::getData()
{
    if (!accelerometer()) {
        qDebug() << "Not found accelerometer";
        return {};
    }

    auto readingData { accelerometer()->reading() };
    QByteArray result = QString("%1%2%3").arg(readingData->x(),
                                              readingData->y(),
                                              readingData->z()).toUtf8();
    return result;
}

QString AccelerometerEntropySource::name()
{
    return "Accelerometer";
}

QSharedPointer<QAccelerometer> AccelerometerEntropySource::accelerometer()
{
    if (auto accelerometer = qSharedPointerObjectCast<QAccelerometer>(sensor()))
    {
        return accelerometer;
    }

    return nullptr;
}
