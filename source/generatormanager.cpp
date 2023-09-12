#include <chrono>

#include "generatormanager.h"

GeneratorManager::GeneratorManager() :
    m_accumulator(new PoolsAccumulator),
    m_pools(m_accumulator->pools()),
    m_generator(new Generator),
    m_reseedCount(0)
{
    qDebug() << "Start generator work";

    connect(m_accumulator.data(), &PoolsAccumulator::sourcesChanged, this, &GeneratorManager::sourcesChanged);
}

GeneratorManager::GeneratorManager(const quint32 _seed)
    : GeneratorManager()
{
    seed(_seed);
}

GeneratorManager::GeneratorManager(const QVector<quint32>& _seeds)
    : GeneratorManager()
{
    seed(_seeds);
}

GeneratorManager::~GeneratorManager()
{
    qDebug() << "Stop generator work";
}

void GeneratorManager::registerFortunaGenerator(const char* uri)
{
    qDebug() << "Register type: " << uri;
    if (QString::fromUtf8(uri).isEmpty())
    {
        qWarning() << "Can't register empty uri";
        return;
    }

    qmlRegisterType<GeneratorManager>(uri, 1, 0, "Fortuna");
    PoolsAccumulator::registerSources(uri);
}

bool GeneratorManager::addSource(const QSharedPointer<AbstractEntropySource>& _source)
{
    if (!_source)
    {
        qWarning() << "Nothing to add";
        return false;
    }

    if (!m_accumulator)
    {
        qWarning() << "Unable to add source now";
        return false;
    }

    m_accumulator->addSource(_source);
    return true;
}

bool GeneratorManager::addSource(AbstractEntropySource *_source)
{
    if (!m_accumulator)
        return false;

    m_accumulator->addSource(_source);
    return true;
}

bool GeneratorManager::addSource(const QVector<QSharedPointer<AbstractEntropySource>>& _sources)
{
    if (_sources.isEmpty())
    {
        qWarning() << "Nothing to add";
        return false;
    }

    for (const auto& source : _sources)
        addSource(source);

    return true;
}

bool GeneratorManager::addSource(const QSharedPointer<QSensor>& _sensor)
{
    if (!m_accumulator)
    {
        qWarning() << "Unable to add source now";
        return false;
    }

    m_accumulator->addSource(_sensor);
    return true;
}

bool GeneratorManager::addSource(const QByteArray &_type)
{
    if (!m_accumulator)
    {
        qWarning() << "Unable to add source now";
        return false;
    }

    m_accumulator->addSource(_type);
    return true;
}

QString GeneratorManager::getSourcesStr()
{
    QString emptyStr = tr("Нет");
    if (!m_accumulator)
        return emptyStr;

    QString sourcesStr = m_accumulator->sourcesStr();
    return sourcesStr.isEmpty() ? emptyStr : sourcesStr;
}

bool GeneratorManager::generationEnabled()
{
    if (!m_accumulator)
        return false;

    return m_accumulator->sourcesCount() != 0;
}

bool GeneratorManager::prepareEntropy() const
{
    if (!m_pools)
        return false;

    if (m_pools->at(0).getSize() < GlobalConstants::MIN_POOL_SIZE)
        collectFirstPool();

    return m_pools->at(0).getSize() >= GlobalConstants::MIN_POOL_SIZE;
}

void GeneratorManager::clearSources()
{
    qDebug() << "Clear all entropy sources";
    if (!m_accumulator)
    {
        qWarning() << "Unable to clear source now";
        return;
    }

    m_accumulator->clearSources();
}

void GeneratorManager::seed(const QVector<quint32>& _seeds)
{
    if (!m_generator)
    {
        qWarning() << "Error seed the generator";
        return;
    }

    QVector<quint32> buffer(GlobalConstants::MIN_POOL_SIZE);
    std::seed_seq seedSeq(_seeds.begin(), _seeds.end());
    seedSeq.generate(buffer.begin(), buffer.end());

    m_generator->reseed(GlobalConstants::convertToBytes(buffer));
}

void GeneratorManager::seed(quint32 _seed)
{
    if (!m_generator)
    {
        qWarning() << "Error seed the generator";
        return;
    }

    m_generator->reseed(GlobalConstants::convertToBytes(_seed));
}

void GeneratorManager::fillRange(QVector<quint32>& _buffer)
{
    if (!m_generator || !m_accumulator || !m_pools)
    {
        qWarning() << "Can't generate random data";
        return;
    }

    if (!m_accumulator->hasEntropySource())
    {
        qWarning() << "Error! Not found entropy source";
        return;
    }

    /// TODO: Need more concrete conditions for reseed
    if (m_pools->at(0).getSize() >= GlobalConstants::MIN_POOL_SIZE)
    {
        //qDebug() << "Reseed >>>";
        QByteArray seeds(m_pools->size() * GlobalConstants::ENTROPY_POOL_COUNT, 0);
        auto seedIt {seeds.begin()};
        quint64 powerOfTwo {1};

        if (m_reseedCount == std::numeric_limits<quint64>::max())
            m_reseedCount = 0;
        ++m_reseedCount;

        for (int i = 0; i < m_pools->size(); ++i)
        {
            if (i == 0 || m_reseedCount % powerOfTwo == 0)
            {
                QByteArray currPool {(*m_pools)[i].getAndResetValue()};
                seedIt = std::copy(currPool.begin(), currPool.end(), seedIt);
            }

            powerOfTwo <<= 1;
        }
        if (!seeds.isEmpty())
            m_generator->reseed(seeds);
    }

    m_generator->fillBuffer(_buffer);
}

quint32 GeneratorManager::generate()
{
    QVector<quint32> result(1, 0);
    fillRange(result);
    return result.at(0);
}

QVariantList GeneratorManager::generateRange(const quint32 _count)
{
    if (_count <= 0)
    {
        qWarning() << QString("Can't generate %1 digits").arg(_count);
        return {};
    }

    QVector<quint32> buffer(_count, 0);
    fillRange(buffer);

    QVariantList result;
    for (const auto& el : qAsConst(buffer))
        result << el;

    return result;
}

const QScopedPointer<PoolsAccumulator>& GeneratorManager::accumulator() const
{
    return m_accumulator;
}

bool GeneratorManager::collectFirstPool() const
{
    bool isReady {false};
    if (!m_pools)
    {
        qWarning() << "Don't have entropy";
        return false;
    }

    if (m_pools->at(0).getSize() > GlobalConstants::MIN_POOL_SIZE)
        return true;

    qDebug().noquote() << QString("Waiting while entropy to be ready (%1 seconds max)")
                              .arg(GlobalConstants::POOL_COMPLETED_MAX_SEC);

    const auto startPoint = std::chrono::steady_clock::now();
    auto endPoint = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::seconds>(endPoint - startPoint)
           < std::chrono::seconds(GlobalConstants::POOL_COMPLETED_MAX_SEC))
    {
        qDebug() << "Wait...";
//        QThread::sleep(1);
        QEventLoop loop;
        QTimer::singleShot(2000, [&loop]() {
            loop.quit();
        });
        loop.exec();
        if (m_pools->at(0).getSize() > GlobalConstants::MIN_POOL_SIZE)
        {
            qDebug() << "Entropy is ready";
            isReady = true;
            break;
        }
        endPoint = std::chrono::steady_clock::now();
    }

    return isReady;
}

QQmlListProperty<AbstractEntropySource> GeneratorManager::entropySources()
{
    return {this, this,
            &sourcesAppend,
            &sourcesCount,
            &sourceAt,
            &sourcesClear};
}

void GeneratorManager::sourcesAppend(QQmlListProperty<AbstractEntropySource>* property, AbstractEntropySource* _source)
{
    auto genManager = reinterpret_cast<GeneratorManager*>(property->data);
    Q_ASSERT(genManager != nullptr);

    genManager->addSource(_source);
}

int GeneratorManager::sourcesCount(QQmlListProperty<AbstractEntropySource> *property)
{
    auto genManager = reinterpret_cast<GeneratorManager*>(property->data);
    Q_ASSERT(genManager != nullptr && genManager->accumulator() != nullptr);

    return genManager->accumulator()->sourcesCount();
}

void GeneratorManager::sourcesClear(QQmlListProperty<AbstractEntropySource> *property)
{
    auto genManager = reinterpret_cast<GeneratorManager*>(property->data);
    Q_ASSERT(genManager != nullptr);

    genManager->clearSources();
}

AbstractEntropySource* GeneratorManager::sourceAt(QQmlListProperty<AbstractEntropySource>* _property, int _index)
{
    auto genManager = reinterpret_cast<GeneratorManager*>(_property->data);
    Q_ASSERT(genManager != nullptr && genManager->accumulator() != nullptr);

    return genManager->accumulator()->at(_index);
}
