#ifndef COMPASSENTROPYSOURCE_H
#define COMPASSENTROPYSOURCE_H

#include <QCompass>
#include <QSharedPointer>

#include "qsensorentropysource.h"

class CompassEntropySource : public QSensorEntropySource
{
public:
    CompassEntropySource(QObject* parent = nullptr);

    QByteArray getData() override;
    QString name() override;

    QSharedPointer<QCompass> compass();
};

#endif // COMPASSENTROPYSOURCE_H
