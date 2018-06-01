#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

#include <QtWidgets/QMainWindow>
#include "ui_cryptography.h"

class Cryptography : public QMainWindow
{
	Q_OBJECT

public:
	Cryptography(QWidget *parent = 0);
	~Cryptography();

private slots:
    void on_actionNew_triggered();

    void on_actionOpen_triggered();

    void on_actionSave_triggered();

    void on_actionSave_As_triggered();

    void on_actionFont_triggered();

private:
	Ui::CryptographyClass ui;
	QString currentFile;
};

#endif // CRYPTOGRAPHY_H
