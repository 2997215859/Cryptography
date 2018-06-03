#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFile>
#include <QMessageBox>

#include <Cryptopp/randpool.h>
#include <Cryptopp/rsa.h>
#include <Cryptopp/hex.h>
#include <Cryptopp/files.h>
#include <Cryptopp/osrng.h>

namespace Ui {
class MainWindow;
}

using namespace CryptoPP;
using namespace std;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_pushButton_gen_a_clicked();

    void on_pushButton_gen_b_clicked();

private:
    Ui::MainWindow *ui;

    InvertibleRSAFunction paramsA;
    RSA::PrivateKey privateKeyA;
    RSA::PublicKey publicKeyA;

    InvertibleRSAFunction paramsB;
    RSA::PrivateKey privateKeyB;
    RSA::PublicKey publicKeyB;

public:
    void GenerateRSAKey(int keyLength, const std::string privFilename, const std::string pubFilename, const std::string seed);
    void GenerateRSAKeyA();
    void GenerateRSAKeyB();
    void SavePublicKey(const std::string& filename, const CryptoPP::PublicKey& key);
    void SavePrivateKey(const std::string& filename, const CryptoPP::PrivateKey& key);
    void Save(const std::string& filename, const CryptoPP::BufferedTransformation& bt);
    void LoadPublicKey(const std::string& filename, CryptoPP::PublicKey& key);
    void Load(const std::string& filename, CryptoPP::BufferedTransformation& bt);

    void SaveHexPrivateKey(const std::string& filename, const CryptoPP::PrivateKey& key);
    void SaveHexPublicKey(const std::string& filename, const CryptoPP::PublicKey& key);
    void SaveHex(const std::string& filename, const CryptoPP::BufferedTransformation& bt);
};

#endif // MAINWINDOW_H
