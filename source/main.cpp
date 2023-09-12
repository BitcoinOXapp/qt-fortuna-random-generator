//#include <QGuiApplication>
//#include <QQmlApplicationEngine>
//#include <QQmlContext>
//#include <QtCore>

//#include "generatormanager.h"
//#include "entropy/sources/freememoryentropysource.h"
//#include "entropy/sources/qsensors/accelerometerentropysource.h"

int main() //int argc, char *argv[])
{
//#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
//    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
//#endif
//    QGuiApplication app(argc, argv);

//    QQmlApplicationEngine engine;

//    qDebug() << "\n === \n Fortuna generator start \n === \n";

//    /// Fortuna generator demonstration
//    GeneratorManager genManager(100);
//    genManager.seed({1, 2, 3, 4, 5});

//    /// Add sources
//    QSharedPointer<FreeMemoryEntropySource> freeMemorySource(new FreeMemoryEntropySource());
//    QSharedPointer<AccelerometerEntropySource> accelerometerSource(new AccelerometerEntropySource());
//    genManager.addSource(freeMemorySource);
//    genManager.addSource(accelerometerSource);

//    QThread::sleep(2);
//    if (!genManager.prepareEntropy())
//    {
//        qWarning() << "Failed to collect entropy";
//        /// TODO
//        // genManager.deinit();
//    }
//    else
//    {
//        qDebug() << "Generate...";
//        for (quint32 i = 1; i <= 10; ++i)
//        {
//            QVector<quint32> _result(i);
//            QThread::msleep(100);
//            genManager.fillRange(_result);
//            qDebug() << _result;
//        }
//    }

//    auto _context = engine.rootContext();
//    _context->setContextProperty("fortuna", &generator);
//    qmlRegisterType<GeneratorManager>("CustomComponents", 1, 0, "QFortunaRandomGenerator");
//    const QUrl url(QStringLiteral("qrc:/main.qml"));
//    QObject::connect(&engine, &QQmlApplicationEngine::objectCreated,
//        &app, [url](QObject *obj, const QUrl &objUrl) {
//            if (!obj && url == objUrl)
//                QCoreApplication::exit(-1);
//        }, Qt::QueuedConnection);
//    engine.load(url);

    return 0; //app.exec();
}
