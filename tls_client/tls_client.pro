TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += -std=c++17

SOURCES += \
    main.cpp

INCLUDEPATH += $$PWD/../sha1_farm

LIBS+= -lboost_system -lssl -lcrypto -lpthread -lgmp -L$$PWD/../sha1_farm -lSha1Farm
