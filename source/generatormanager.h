#ifndef GENERATORMANAGER_H
#define GENERATORMANAGER_H

#include <QObject>
#include <QtQml>

#include "generator.h"
#include "entropy/poolsaccumulator.h"

///
/// \brief The GeneratorManager class - General manager for work Fortuna generator
///
class GeneratorManager : public QObject
{
    Q_OBJECT

    Q_PROPERTY(QQmlListProperty<AbstractEntropySource> sources READ entropySources NOTIFY sourcesChanged)
    Q_PROPERTY(QString sourcesStr READ getSourcesStr NOTIFY sourcesChanged)
    Q_PROPERTY(bool generationEnabled READ generationEnabled NOTIFY sourcesChanged)

public:
    GeneratorManager();
    GeneratorManager(const quint32 _seed);
    GeneratorManager(const QVector<quint32>& _seeds);
    ~GeneratorManager();

    static void registerFortunaGenerator(const char* uri = GlobalConstants::PLUGIN_NAME);

    ///
    /// \brief addSource - Add new entropy source
    /// \param _source
    /// \return Adding was successful
    ///
    Q_INVOKABLE bool addSource(AbstractEntropySource* _source);
    Q_INVOKABLE bool addSource(const QByteArray& _type);
    /// TODO ?
    bool addSource(const QSharedPointer<AbstractEntropySource>& _source);
    bool addSource(const QVector<QSharedPointer<AbstractEntropySource>>& _sources);
    bool addSource(const QSharedPointer<QSensor>& _sensor);

    QString getSourcesStr();
    bool generationEnabled();

    ///
    /// \brief prepareEntropy - Prepare entropy for generator
    /// \return ready/not ready
    ///
    Q_INVOKABLE bool prepareEntropy() const;
    Q_INVOKABLE void clearSources();

    ///
    /// \brief seed - Specify seeds for generator
    /// \param _seeds
    ///
    void seed(const QVector<quint32>& _seeds);
    void seed(const quint32 _seed = 1);

    ///
    /// \brief fillRange - Fill _buffer with pseudo random values
    /// \param _buffer - target buffer
    ///
    void fillRange(QVector<quint32>& _buffer);
    ///
    /// \brief generate - Generate one byte pseudo random data
    /// \return
    ///
    Q_INVOKABLE quint32 generate();
    Q_INVOKABLE QVariantList generateRange(const quint32 _count);

    const QScopedPointer<PoolsAccumulator>& accumulator() const;

private:
    ///
    /// \brief collectFirstPool - Wait until the first pool is ready
    /// \return Pool ready/not ready
    ///
    bool collectFirstPool() const;

    /// Entropy source property in qml
    QQmlListProperty<AbstractEntropySource> entropySources();
    static void sourcesAppend(QQmlListProperty<AbstractEntropySource>* _property, AbstractEntropySource* _source);
    static int sourcesCount(QQmlListProperty<AbstractEntropySource>* _property);
    static void sourcesClear(QQmlListProperty<AbstractEntropySource>* _property);
    static AbstractEntropySource* sourceAt(QQmlListProperty<AbstractEntropySource>* _property, int _index);

private:
    QScopedPointer<PoolsAccumulator> m_accumulator;     // need to handle pools
    QSharedPointer<Pools> m_pools;                      // entropy pools
    QScopedPointer<Generator> m_generator;              // internal generator
    quint64 m_reseedCount;                              // counter for choose pools

signals:
    void sourcesChanged();
};

#endif // GENERATORMANAGER_H
