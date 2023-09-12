QT += qml sensors

ABSOLUTE_PATH = $$absolute_path($$PWD/../source)
INCLUDEPATH += $$ABSOLUTE_PATH

for (abi, ANDROID_ABIS): {
ANDROID_EXTRA_LIBS += \
    $$PWD/Plugins/libQtFortunaGenerator_arm64-v8a.so
}

HEADERS += \
    $$PWD/../source/globaldefs.h
