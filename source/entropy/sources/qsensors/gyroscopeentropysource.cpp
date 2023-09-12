#include "gyroscopeentropysource.h"

#include <QDebug>

GyroscopeEntropySource::GyroscopeEntropySource(QObject *parent)
    : QSensorEntropySource(parent)
{
    qDebug() << "Initialize gyroscope >>>>";
    QSharedPointer<QGyroscope> sensor(new QGyroscope);
    initSensor(sensor);

    if (gyroscope())
        qDebug() << "Gyroscope init OK";
    else
        qDebug() << "Error gyroscope init";
}

QByteArray GyroscopeEntropySource::getData()
{
    if (!gyroscope()) {
        qDebug() << "Not found gyroscope";
        return {};
    }

    auto readingData { gyroscope()->reading() };
    QByteArray result = QString("%1%2%3").arg(readingData->x(),
                                              readingData->y(),
                                              readingData->z()).toUtf8();
    return result;
}

QString GyroscopeEntropySource::name()
{
    return "Gyroscope";
}

QSharedPointer<QGyroscope> GyroscopeEntropySource::gyroscope()
{
    if (auto gyroscope = qSharedPointerObjectCast<QGyroscope>(sensor()))
    {
        return gyroscope;
    }

    return nullptr;
}
