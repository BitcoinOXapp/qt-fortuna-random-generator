#include "qsensorentropysource.h"

QSensorEntropySource::QSensorEntropySource(QObject* parent) :
    AbstractEntropySource(parent),
    m_sensor(nullptr)
{
}

QSharedPointer<QSensor> QSensorEntropySource::sensor()
{
    return m_sensor;
}

void QSensorEntropySource::initSensor(const QByteArray& _type)
{
    if (m_sensor)
        disconnectAll();

    m_sensor = QSharedPointer<QSensor>(new QSensor(_type, this));
    createConnections();

}

void QSensorEntropySource::initSensor(const QSharedPointer<QSensor>& _type)
{
    if (m_sensor)
        disconnectAll();

    m_sensor = _type;
    createConnections();
}

void QSensorEntropySource::startCollect()
{
    if (!m_sensor->isActive())
        m_sensor->start();
}

void QSensorEntropySource::stopCollect()
{
    if (m_sensor && m_sensor->isActive())
        m_sensor->stop();
}

void QSensorEntropySource::createConnections()
{
    connect(m_sensor.data(), &QSensor::readingChanged, this, &AbstractEntropySource::updatePool);
}

void QSensorEntropySource::disconnectAll()
{
    disconnect(m_sensor.data(), &QSensor::readingChanged, this, &AbstractEntropySource::updatePool);
}
