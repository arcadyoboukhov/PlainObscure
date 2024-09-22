QT       += core gui
QT       += core sql

LIBS += -lz

# Specify the correct library path for OpenSSL
LIBS += -L"C:/msys64/mingw64/lib" -lssl -lcrypto



# Include OpenCV headers
INCLUDEPATH += C:/opencv/build/include


INCLUDEPATH += $$PWD/include

TARGET = LSBSteganography
TEMPLATE = app

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# Update the path for your source files
SOURCES += \
    src/form.cpp \
    src/main.cpp \
    src/mainwindow.cpp \
    src/manager.cpp \
    src/password.cpp

# Update the path for your header files
HEADERS += \
    src/form.h \
    src/mainwindow.h \
    src/manager.h \
    src/password.h

FORMS += \
    src/form.ui \
    src/mainwindow.ui \
    src/manager.ui \
    src/password.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    resource.qrc
