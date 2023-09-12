#include "lightentropysource.h"

#include <QDebug>

LightEntropySource::LightEntropySource(QObject *parent)
    : QSensorEntropySource(parent)
{
    qDebug() << "Initialize lightSensor >>>>";
    QSharedPointer<QLightSensor> sensor(new QLightSensor);
    initSensor(sensor);

    if (lightSensor())
        qDebug() << "LightSensor init OK";
    else
        qDebug() << "Error lightSensor init";
}

QByteArray LightEntropySource::getData()
{
    if (!lightSensor()) {
        qDebug() << "Not found lightSensor";
        return {};
    }

    auto readingData { lightSensor()->reading() };
    QByteArray result = QString("%1%2%3").arg(readingData->lux()).toUtf8();
    return result;
}

QString LightEntropySource::name()
{
    return "Light Sensor";
}

QSharedPointer<QLightSensor> LightEntropySource::lightSensor()
{
    if (auto lightSensor = qSharedPointerObjectCast<QLightSensor>(sensor()))
    {
        return lightSensor;
    }

    return nullptr;
}
