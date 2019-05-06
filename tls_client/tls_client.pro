TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += -std=c++17

SOURCES += \
    main.cpp

INCLUDEPATH += $$PWD/../Sha1Farm

LIBS+= -lboost_system -lssl -lcrypto -lpthread -L$$PWD/../Sha1Farm -lSha1Farm
