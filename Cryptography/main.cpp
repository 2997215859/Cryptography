#include "mainwindow.h"
#include <QApplication>
#include <QTextStream>
#include <QString>
#include <QDebug>

#include <string>

#include <iostream>

#pragma comment(lib, "cryptlib.lib")

using namespace std;

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
