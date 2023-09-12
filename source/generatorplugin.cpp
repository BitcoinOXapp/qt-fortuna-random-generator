#include "generatorplugin.h"
#include "generatormanager.h"

GeneratorPlugin::GeneratorPlugin()
{
    qDebug() << "Generator Plugin loaded";
    registerTypes();
}

void GeneratorPlugin::registerTypes()
{
    GeneratorManager::registerFortunaGenerator();
}

void GeneratorPlugin::registerTypes(const char* uri)
{
    QString uriStr = QString::fromUtf8(uri);
    if (uriStr.isEmpty())
    {
        qWarning() << "Can't register empty uri";
    }
    else
    {
        GeneratorManager::registerFortunaGenerator(uri);
    }
}
