TEMPLATE = lib
TARGET = QtFortunaGenerator
QT += qml quick sensors
CONFIG += plugin c++11

DESTDIR = $$PWD/Plugins

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

HEADERS += \
#    ../source/aesblockcipher.h \
#    ../source/cryptoprocessor.cpp \
    ../source/entropy/datacollector.h \
    ../source/entropy/poolsaccumulator.h \
    ../source/entropy/sources/abstractentropysource.h \
    ../source/entropy/sources/qsensors/accelerometerentropysource.h \
    ../source/entropy/sources/qsensors/compassentropysource.h \
    ../source/entropy/sources/qsensors/gyroscopeentropysource.h \
    ../source/entropy/sources/qsensors/lightentropysource.h \
    ../source/entropy/sources/qsensors/qsensorentropysource.h \
    ../source/entropy/sources/freememoryentropysource.h \
    ../source/entropy/pool.h \
    ../source/entropy/sources/timingentropysource.h \
    ../source/generator.h \
    ../source/generatormanager.h \
    ../source/generatorplugin.h \
    ../source/globaldefs.h


SOURCES += \
#    ../source/aesblockcipher.cpp \
#    ../source/cryptoprocessor.h \
    ../source/entropy/datacollector.cpp \
    ../source/entropy/poolsaccumulator.cpp \
    ../source/entropy/sources/abstractentropysource.cpp \
    ../source/entropy/sources/qsensors/accelerometerentropysource.cpp \
    ../source/entropy/sources/qsensors/compassentropysource.cpp \
    ../source/entropy/sources/qsensors/gyroscopeentropysource.cpp \
    ../source/entropy/sources/qsensors/lightentropysource.cpp \
    ../source/entropy/sources/qsensors/qsensorentropysource.cpp \
    ../source/entropy/sources/freememoryentropysource.cpp \
    ../source/entropy/pool.cpp \
    ../source/entropy/sources/timingentropysource.cpp \
    ../source/generator.cpp \
    ../source/generatormanager.cpp \
    ../source/generatorplugin.cpp \
    ../source/main.cpp

# Additional import path used to resolve QML modules in Qt Creator's code model
QML_IMPORT_PATH =

# Additional import path used to resolve QML modules just for Qt Quick Designer
QML_DESIGNER_IMPORT_PATH =

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
