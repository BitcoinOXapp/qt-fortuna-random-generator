#include "pool.h"
#include <QDebug>

Pool::Pool() :
    m_value(0),
    m_size(0),
    m_hash(QCryptographicHash::Algorithm::Sha256)
{
}

Pool::Pool(const Pool& _other) :
    m_value(_other.m_value),
    m_size(_other.m_size),
    m_hash(QCryptographicHash::Algorithm::Sha256)
{
}

void Pool::addData(const QByteArray &_inputData)
{
    QMutexLocker locker(&m_mutex);
    if (_inputData.size() > 32)
    {
        qWarning() << "Input data is very large: " << _inputData.size()
                   << "Max size: 32";
        return;
    }

    m_size += _inputData.size();
    m_hash.addData(_inputData);
    m_value = m_hash.result();
}

QByteArray Pool::getAndResetValue()
{
    QMutexLocker locker(&m_mutex);
    m_size = 0;
    return m_value;
}

quint64 Pool::getSize() const
{
    QMutexLocker locker(&m_mutex);
    return m_size;
}
