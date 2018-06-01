#include "cryptography.h"
#include <QMessageBox>
#include <QFile>
#include <QString>
#include <QTextStream>
#include <QFileDialog>
#include <QFont>
#include <QFontDialog>

Cryptography::Cryptography(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	this->setCentralWidget(ui.textEdit_2);
}

Cryptography::~Cryptography()
{

}

void Cryptography::on_actionNew_triggered()
{
    currentFile.clear();
    ui.textEdit_2->setText(QString());
}

void Cryptography::on_actionOpen_triggered()
{
    QString fileName = QFileDialog::getOpenFileName(this, "Open this file");
    QFile file(fileName);
    currentFile = fileName;
    if (!file.open(QIODevice::ReadOnly | QFile::Text)) {
        QMessageBox::warning(this, "warning", "Cannot open file: " + file.errorString());
        return;
    }
    setWindowTitle(fileName);
    QTextStream in(&file);
    QString text = in.readAll();
    ui.textEdit_2->setText(text);
    file.close();
}

void Cryptography::on_actionSave_triggered()
{
    QString fileName;
    if (currentFile.isEmpty()) {
        fileName = QFileDialog::getSaveFileName(this, "Save");
        currentFile = fileName;
    } else {
        fileName = currentFile;
    }

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QFile::Text)) {
        QMessageBox::warning(this, "warning", "Cannot save file: " + file.errorString());
        return;
    }
    setWindowTitle(fileName);
    QTextStream out(&file);
    QString text = ui.textEdit_2->toPlainText();
    out << text;
    file.close();
}

void Cryptography::on_actionSave_As_triggered()
{
    QString fileName = QFileDialog::getSaveFileName(this, "Save as");
    QFile file(fileName);

    if (!file.open(QFile::WriteOnly | QFile::Text)) {
        QMessageBox::warning(this, "Warning", "Cannot save file: " + file.errorString());
        return;
    }
    currentFile = fileName;
    setWindowTitle(fileName);
    QTextStream out(&file);
    QString text = ui.textEdit_2->toPlainText();
    out << text;
    file.close();
}

void Cryptography::on_actionFont_triggered()
{
    bool fontSelected;
    QFont font = QFontDialog::getFont(&fontSelected, this);
    if (fontSelected)
            ui.textEdit_2->setFont(font);
}
