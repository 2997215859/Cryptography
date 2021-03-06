#-------------------------------------------------
#
# Project created by QtCreator 2018-06-02T11:50:06
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Cryptography
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
        main.cpp \
        mainwindow.cpp

HEADERS += \
        mainwindow.h \

FORMS += \
        mainwindow.ui

INCLUDEPATH += .\include\

QMAKE_CXXFLAGS_DEBUG += /MDd
QMAKE_CXXFLAGS_RELEASE += /MD

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/lib/Output/release/ -lcryptlib
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/lib/Output/debug/ -lcryptlib
else:unix: LIBS += -L$$PWD/lib/Output/ -lcryptlib

INCLUDEPATH += $$PWD/lib/Output/Debug
DEPENDPATH += $$PWD/lib/Output/Debug

win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/lib/Output/release/libcryptlib.a
else:win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/lib/Output/debug/libcryptlib.a
else:win32:!win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/lib/Output/release/cryptlib.lib
else:win32:!win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/lib/Output/debug/cryptlib.lib
else:unix: PRE_TARGETDEPS += $$PWD/lib/Output/libcryptlib.a
