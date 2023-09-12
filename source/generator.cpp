#include <QDebug>

#include "generator.h"

Generator::Generator() :
    m_key(32, 0),
    m_counter(16),
    m_hash(QCryptographicHash::Algorithm::Sha256)
{
}

void Generator::fillBuffer(QVector<quint32>& _outBuffer)
{
    int bufferIndex {0};
    while (bufferIndex < _outBuffer.size())
    {
        auto currentBlock { generateBlock() };

        if (currentBlock.size() <= 4)
        {
            qWarning() << "Error generate block";
            return;
        }

        for (int i = 0; i < currentBlock.size() - 4; i += 4, ++bufferIndex)
        {
            quint32 tempValue = ((quint32)currentBlock[i] << 24)
                                | ((quint32)currentBlock[i + 1] << 16)
                                | ((quint32)currentBlock[i + 2] << 8)
                                | (quint32)currentBlock[i + 3];
            _outBuffer[bufferIndex] = tempValue;

            if (bufferIndex == _outBuffer.size() - 1)
            {
                auto currentBlock {generateBlock()};
                updateKey(currentBlock);
                incrementCounter();
                return;
            }
        }
    }
}

void Generator::updateKey(const QByteArray& _buffer)
{
    m_hash.addData(m_key);
    m_hash.addData(_buffer);
    m_key = m_hash.result();
    auto keyStr { m_key.toStdString() };
    auto userKey = reinterpret_cast<const unsigned char*>(keyStr.c_str());
    AES_set_encrypt_key(userKey, 128, &m_aesKey);
//    Buffer tempBuffer(m_key.size());
//    for (int i = 0; i < m_key.size(); ++i)
//    {
//        tempBuffer[i] = static_cast<quint8>(m_key[i]);
//    }
//    processor.makeKey(tempBuffer, tempBuffer.size() * 8, 1);
    incrementCounter();
}

void Generator::updateKey(const Buffer &_buffer)
{
    QByteArray tempBuffer(_buffer.size(), 0);
    for (int i = 0; i < _buffer.size(); ++i)
    {
        tempBuffer[i] = static_cast<qint8>(_buffer[i]);
    }
    updateKey(tempBuffer);
}

void Generator::reseed(const QByteArray &_seed)
{
    /// DOTO: only key update?
    updateKey(_seed);
}

Buffer Generator::generateBlock()
{
//    Buffer resultBuffer { processor.encrypt(m_counter) };
//    Buffer resultBuffer { processor.Aes128Encrypt(tempBuffer, m_counter) };

    std::string resultStr;
    // The cipher has to be multiples of the block size (16 bytes)
    auto cipherSize = ((m_counter.size() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    resultStr.resize(cipherSize);

    std::string counterStr;
    counterStr.resize(m_counter.size());
    for (int i = 0; i < m_counter.size(); ++i)
    {
        counterStr[i] = static_cast<qint8>(m_counter[i]);
    }

    AES_encrypt(reinterpret_cast<const unsigned char*>(counterStr.c_str()),
                reinterpret_cast<unsigned char*>(&resultStr[0]),
                &m_aesKey);

    Buffer resultBuffer(resultStr.size(), 0);
    for (size_t i = 0; i < resultStr.size(); ++i)
    {
        resultBuffer[i] = static_cast<quint8>(resultStr[i]);
    }

    incrementCounter();
    return resultBuffer;
}

void Generator::incrementCounter()
{
    for (int i = 0 ; i < m_counter.size(); ++i)
    {
        if (m_counter[i] == std::numeric_limits<quint8>::max()) {
            if (i != m_counter.size() - 1)
            {
                continue;
            }

            m_counter.fill(0);
            ++m_counter[0];
            break;
        }

        ++m_counter[i];
        break;
    }
}
