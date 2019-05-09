TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += -std=c++11 -O3

INCLUDEPATH += $$PWD/../sha1_farm

SOURCES += \
    main.cpp

LIBS += -lcrypto -lpthread -L$$PWD/../sha1_farm -lSha1Farm -lgmp
