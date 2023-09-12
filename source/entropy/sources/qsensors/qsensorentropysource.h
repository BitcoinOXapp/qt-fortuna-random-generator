#ifndef QSENSORENTROPYSOURCE_H
#define QSENSORENTROPYSOURCE_H

#include <QSensor>

#include "../abstractentropysource.h"

class QSensorEntropySource : public AbstractEntropySource
{
public:
    QSensorEntropySource(QObject* parent = nullptr);

    QSharedPointer<QSensor> sensor();
    void initSensor(const QByteArray& _type);
    void initSensor(const QSharedPointer<QSensor>& _type);

    void startCollect() override;
    void stopCollect() override;

private:
    void createConnections();
    void disconnectAll();

private:
    QSharedPointer<QSensor> m_sensor;
};

#endif // QSENSORENTROPYSOURCE_H
