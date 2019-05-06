TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += -std=c++17 -O3

INCLUDEPATH += $$PWD/../Sha1Farm

SOURCES += \
    main.cpp

LIBS += -lcrypto -lpthread -L$$PWD/../Sha1Farm -lSha1Farm
