# Qt Fortuna random generator



## Description

Pseudo-random number generation module Fortuna (PRNG). Designed to generate random numbers using **QSensors** as entropy sources (QAccelerometer, QCompass, QGyroscope, QLightSensor).

There are two parts to Fortuna:
1) The internal generator - takes a fixed-size seed
and generates arbitrary amounts of pseudorandom data (**Generator**)
2) The accumulator - collects and pools entropy from various sources and occasionally reseeds the
generator (**PoolsAccumulator**)

**GeneratorManager** is used to manage them. It sets up and starts the generator, sets entropy sources and reseed the generator from time to time.

The generator is basically just a AES block cipher in counter mode. The internal state of the generator consists of a 256-bit block cipher key and a 128-bit counter. If a user or application asks for random data, the generator runs its algorithm and generates pseudorandom data.
After every request we generate an extra 256 bits of pseudorandom data and use that as the new key for the block cipher.
We can then forget the old key, thereby eliminating any possibility of leaking information about old requests.

The accumulator collects real random data to **pools** from various **entropy sources**.
Each source can produce events containing entropy at any point in time. In addition, you should add as many timing sources as practical. The accumulator will be concatenating various events from different sources.
To reseed the generator, we need to pool events in a pool large enough. There are 32 pools. Each pool conceptually contains a unbounded string of bytes. That string is used is as the input to a hash function. Each source distributes its random events over the pools in a cyclical fashion. This ensures that the entropy from each source is distributed more or less evenly over the pools.


## How to use

Download the repository to the **/3rdparty** folder at the root of your project.

```
cd 3rdparty
git clone https://gl.infra.techcd.ru:6443/qt-3rdparty/qt-fortuna-random-generator.git

```

Further, you can work with the module in two ways:
1) Include all sources. To do this, specify in the .pro file of your project the path to _FortunaGenerator.pri_:
```
    include(3rdparty/project/FortunaGenerator.pri)
    DEFINES += QTFORTUANGENERATOR_SOURCES

```
To use the generation methods, add header **#include "generatorManager.h"**, and register the type to access in qml **GeneratorManager::registerFortunaGenerator()**
Into qml you can use **import FortunaGenerator 1.0** and it will be possible to work with the class **Fortuna { }**

2) Include plugin. To do this, specify in the .pro file of your project the path to _FortunaGeneratorPlugin.pri_:
```
    include(3rdparty/project/FortunaGeneratorPlugin.pri)
    DEFINES += QTFORTUANGENERATOR_PLUGIN

```
To use the plugin methods, add header **#include "generatorManager.h"** and load it by name **GlobalConstants::PLUGIN_FILE_NAME**
```
    QPluginLoader pluginLoader(GlobalConstants::PLUGIN_FILE_NAME);
    auto genPlugin = qobject_cast<QQmlExtensionPlugin*>(pluginLoader.instance());
    if (!genPlugin)
    {
        qDebug() << "Failed to load plugin:" << pluginLoader.errorString();
        return 0;
    }

```
After that, add in qml **import FortunaGenerator 1.0** and it will be possible to work with the class **Fortuna { }**

## Examples

Android

For the generator, it is necessary to initialize the list of entropy sources
```
    Fortuna {
        id: generator
        sources: [
            AccelerometerEntropySource {},
            CompassEntropySource {},
            GyroscopeEntropySource {},
            LightEntropySource {}
        ]
    }
```
Four entropy sources supported. You can create your own source by inheriting it from the class **QSensorEntropySource** (or base class **AbstractEntropySource**).

It takes some time to prepare the entropy, it is advisable to call **generator.prepareEntropy()** before using

Finally, two methods are provided to generate numbers:
**generator.generate()** - get quint32 random numer
**generator.generateRange(N)** - get list of quint32 random numers

**clearSources()** - clear all the sources

Entropy sources can be added according to their type of QML sensors by **addSource(type)**:
```
    function sensorsSelected() {
        if (accelCheck.checked)
        {
            generator.addSource(accelerometer.type)
        }
        if (compassCheck.checked)
        {
            generator.addSource(compass.type)
        }
        if (gyroCheck.checked)
        {
            generator.addSource(gyroscope.type)
        }
        if (lightCheck.checked)
        {
            generator.addSource(lightSensor.type)
        }

        contentView.pop()
    }

    Accelerometer { id: accelerometer }
    Compass { id: compass }
    Gyroscope { id: gyroscope }
    LightSensor { id: lightSensor }
```

## Architecture
![Architecture](https://github.com/BitcoinOXapp/qt-fortuna-random-generator/blob/main/docs/Fortuna_architecture.png)
## Algorithm
![Algorithm](https://github.com/BitcoinOXapp/qt-fortuna-random-generator/blob/main/docs/Fortuna_algorithm.png)

## Documentation

- [ ] [Description of the Fortuna algorithm](https://www.schneier.com/wp-content/uploads/2015/12/fortuna.pdf)

