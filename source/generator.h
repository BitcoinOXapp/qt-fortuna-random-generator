#ifndef GENERATOR_H
#define GENERATOR_H

#include "globaldefs.h"
#include "openssl/aes.h"
//#include "cryptoprocessor.h"

/// Internal generator - block AES cipher

class Generator
{
public:
    Generator();

    ///
    /// \brief Generator::fillBuffer - Fill buffer with random values
    /// \param _outBuffer Target buffer
    ///
    void fillBuffer(QVector<quint32>& _outBuffer);

    ///
    /// \brief reseed - Reseed generator
    /// \param _seed
    ///
    void reseed(const QByteArray& _seed);

private:
    ///
    /// \brief Generator::generateBlock - Generate bites with AES encrypt
    /// \return
    ///
    Buffer generateBlock();

    ///
    /// \brief Generator::updateKey - Update key with _buffer
    /// \param _buffer
    ///
    void updateKey(const QByteArray& _buffer);
    void updateKey(const Buffer& _buffer);
    ///
    /// \brief Generator::incrementCounter - Counter for generate random block
    ///
    void incrementCounter();

private:
    /// Hash key and counter for encryption
    QByteArray m_key;
    Buffer m_counter;

//    AESBlockCipher processor;
//    CryptoProcessor processor;
    AES_KEY m_aesKey;
    QCryptographicHash m_hash;
};

#endif // GENERATOR_H
