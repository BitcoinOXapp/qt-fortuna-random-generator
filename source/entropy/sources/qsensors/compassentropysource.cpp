#include "compassentropysource.h"

#include <QDebug>

CompassEntropySource::CompassEntropySource(QObject* parent)
    : QSensorEntropySource(parent)
{
    qDebug() << "Initialize compass >>>>";
    QSharedPointer<QCompass> sensor(new QCompass);
    initSensor(sensor);

    if (compass())
        qDebug() << "Compass init OK";
    else
        qDebug() << "Error compass init";
}

QByteArray CompassEntropySource::getData()
{
    if (!compass()) {
        qDebug() << "Not found compass";
        return {};
    }

    auto readingData { compass()->reading() };
    QByteArray result = QString("%1%2%3").arg(readingData->azimuth()).toUtf8();
    return result;
}

QString CompassEntropySource::name()
{
    return "Compass";
}

QSharedPointer<QCompass> CompassEntropySource::compass()
{
    if (auto compass = qSharedPointerObjectCast<QCompass>(sensor()))
    {
        return compass;
    }

    return nullptr;
}
