TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.cpp \
        sha1.c

LIBS += /usr/lib64/libOpenCL.so.1

RESOURCES += \
    sha1.cl
