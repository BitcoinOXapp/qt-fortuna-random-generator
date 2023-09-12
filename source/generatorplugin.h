#ifndef GENERATORPLUGIN_H
#define GENERATORPLUGIN_H

#include <QQmlExtensionPlugin>

class GeneratorPlugin : public QQmlExtensionPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID QQmlExtensionInterface_iid)
public:
    GeneratorPlugin();

    void registerTypes();
    void registerTypes(const char* uri) override;
};

#endif // GENERATORPLUGIN_H
