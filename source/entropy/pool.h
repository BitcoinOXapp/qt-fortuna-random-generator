#ifndef POOL_H
#define POOL_H

#include <QByteArray>
#include <QCryptographicHash>
#include <QMutexLocker>

class Pool
{
public:
    Pool();
    Pool(const Pool& _other);

    void addData(const QByteArray& _inputData);
    QByteArray getAndResetValue();
    quint64 getSize() const;

private:
    QByteArray m_value;
    quint32 m_size;

    mutable QMutex m_mutex;

    QCryptographicHash m_hash;
};

#endif // POOL_H
