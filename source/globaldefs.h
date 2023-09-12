#ifndef GLOBALDEFS_H
#define GLOBALDEFS_H

#include <QtCore>
#include <QByteArray>

#include "entropy/pool.h"

/// Буфер для сырых данных
typedef QVector<quint8> Buffer;
/// Список пулов
typedef QVector<Pool> Pools;

namespace GlobalConstants {
/// Минимальный размер первого pool
static const quint32 MIN_POOL_SIZE = 64;
/// Количество пулов энтропии
static const quint32 ENTROPY_POOL_COUNT = 32;
/// Максимальное время ожидания первого заполнения пула
static const quint32 POOL_COMPLETED_MAX_SEC = 60;
/// Название Fortuna generator плагина
static const char* PLUGIN_NAME = "FortunaGenerator";
static const QLatin1String PLUGIN_FILE_NAME = QLatin1String("libQtFortunaGenerator_arm64-v8a");

static QByteArray convertToBytes(const QVector<quint32>& _buffer)
{
    QByteArray bytesBuffer;
    for (int i = 0; i < _buffer.size(); ++i)
    {
        bytesBuffer.append(static_cast<char>(_buffer[i] >> 24 & 0xFF));
        bytesBuffer.append(static_cast<char>(_buffer[i] >> 16 & 0xFF));
        bytesBuffer.append(static_cast<char>(_buffer[i] >> 8 & 0xFF));
        bytesBuffer.append(static_cast<char>(_buffer[i] & 0xFF));
    }
    return bytesBuffer;
}

static QByteArray convertToBytes(const quint32 _value)
{
    QByteArray bytesBuffer;
    bytesBuffer.append(static_cast<char>(_value >> 24 & 0xFF));
    bytesBuffer.append(static_cast<char>(_value >> 16 & 0xFF));
    bytesBuffer.append(static_cast<char>(_value >> 8 & 0xFF));
    bytesBuffer.append(static_cast<char>(_value & 0xFF));
    return bytesBuffer;
}
}

#endif // GLOBALDEFS_H
