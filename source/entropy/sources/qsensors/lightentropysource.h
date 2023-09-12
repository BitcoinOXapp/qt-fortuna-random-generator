#ifndef LIGHTENTROPYSOURCE_H
#define LIGHTENTROPYSOURCE_H

#include <QLightSensor>
#include <QSharedPointer>

#include "qsensorentropysource.h"

class LightEntropySource : public QSensorEntropySource
{
public:
    LightEntropySource(QObject* parent = nullptr);

    QByteArray getData() override;
    QString name() override;

    QSharedPointer<QLightSensor> lightSensor();
};

#endif // LIGHTENTROPYSOURCE_H
