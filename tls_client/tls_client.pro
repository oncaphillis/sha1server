TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += -std=c++17

SOURCES += \
    main.cpp

LIBS+= -lboost_system -lssl -lcrypto -lpthread
