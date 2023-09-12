#ifndef AESBLOCKCIPHER_H
#define AESBLOCKCIPHER_H

#include <QVector>

class AESBlockCipher
{
public:
    AESBlockCipher();

    void expandKey(QVector<quint8> cipherKey);
    void invertKey();
    void makeKey(QVector<quint8> cipherKey, quint32 keyBits, quint32 direction);
    void makeKey(QVector<quint8> cipherKey, quint32 keyBits);

    QVector<quint8> encrypt(QVector<quint8> pt);
    QVector<quint8> decrypt(QVector<quint8> ct);

    void finalize();
};

#endif // AESBLOCKCIPHER_H
