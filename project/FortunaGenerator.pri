QT += qml quick sensors

ABSOLUTE_PATH = $$absolute_path($$PWD/../source)
INCLUDEPATH += $$ABSOLUTE_PATH

include($$PWD/../openSSL/openssl.pri)
# TARGET = $$qtLibraryTarget($$TARGET)

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
#        $$PWD/../source/aesblockcipher.cpp \
#        $$PWD/../source/cryptoprocessor.cpp \
        $$PWD/../source/entropy/datacollector.cpp \
        $$PWD/../source/entropy/poolsaccumulator.cpp \
        $$PWD/../source/entropy/sources/abstractentropysource.cpp \
        $$PWD/../source/entropy/sources/qsensors/accelerometerentropysource.cpp \
        $$PWD/../source/entropy/sources/qsensors/compassentropysource.cpp \
        $$PWD/../source/entropy/sources/qsensors/gyroscopeentropysource.cpp \
        $$PWD/../source/entropy/sources/qsensors/lightentropysource.cpp \
        $$PWD/../source/entropy/sources/qsensors/qsensorentropysource.cpp \
        $$PWD/../source/entropy/sources/freememoryentropysource.cpp \
        $$PWD/../source/entropy/pool.cpp \
        $$PWD/../source/entropy/sources/timingentropysource.cpp \
        $$PWD/../source/generator.cpp \
        $$PWD/../source/generatormanager.cpp
#        $$PWD/../source/main.cpp

# Additional import path used to resolve QML modules in Qt Creator's code model
#QML_IMPORT_PATH =

# Additional import path used to resolve QML modules just for Qt Quick Designer
#QML_DESIGNER_IMPORT_PATH =

# Default rules for deployment.
#qnx: target.path = /tmp/$${TARGET}/bin
#else: unix:!android: target.path = /opt/$${TARGET}/bin
#!isEmpty(target.path): INSTALLS += target

HEADERS += \
#    $$PWD/../source/aesblockcipher.h \
#    $$PWD/../source/cryptoprocessor.h \
    $$PWD/../source/entropy/datacollector.h \
    $$PWD/../source/entropy/poolsaccumulator.h \
    $$PWD/../source/entropy/sources/abstractentropysource.h \
    $$PWD/../source/entropy/sources/qsensors/accelerometerentropysource.h \
    $$PWD/../source/entropy/sources/qsensors/compassentropysource.h \
    $$PWD/../source/entropy/sources/qsensors/gyroscopeentropysource.h \
    $$PWD/../source/entropy/sources/qsensors/lightentropysource.h \
    $$PWD/../source/entropy/sources/qsensors/qsensorentropysource.h \
    $$PWD/../source/entropy/sources/freememoryentropysource.h \
    $$PWD/../source/entropy/pool.h \
    $$PWD/../source/entropy/sources/timingentropysource.h \
    $$PWD/../source/generator.h \
    $$PWD/../source/generatormanager.h \
    $$PWD/../source/globaldefs.h
