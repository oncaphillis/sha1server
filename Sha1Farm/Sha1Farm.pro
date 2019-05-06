#-------------------------------------------------
#
# Project created by QtCreator 2019-05-06T14:13:27
#
#-------------------------------------------------

QT       -= core gui

TARGET = Sha1Farm
TEMPLATE = lib

CONFIG += staticlib

DEFINES += SHA1FARM_LIBRARY

QMAKE_CXXFLAGS += -std=c++17 -Ofast

SOURCES += \
        sha1farm.cpp

HEADERS += \
        sha1farm.h

unix {
    target.path = /usr/lib
    INSTALLS += target
}
