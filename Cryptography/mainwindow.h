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
#include <Cryptopp/filters.h>
#include <Cryptopp/sha.h>
#include <Cryptopp/md5.h>
#include <Cryptopp/channels.h>
#include <Cryptopp/aes.h>
#include <Cryptopp/modes.h>
#include <Cryptopp/pssr.h>

namespace Ui {
class MainWindow;
}

using namespace CryptoPP;
using namespace std;

class MainWindow : public QMainWindow
{
    Q_OBJECT
    typedef pair<RSA::PrivateKey, RSA::PublicKey> KeyPair;
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_pushButton_gen_a_clicked();

    void on_pushButton_gen_b_clicked();

    void on_pushButton_gen_k_clicked();

    void on_pushButton_crypto_clicked();

private:
    Ui::MainWindow *ui;

    InvertibleRSAFunction paramsA;
    KeyPair keyPairA;

    InvertibleRSAFunction paramsB;
    KeyPair keyPairB;


    SecByteBlock iv;

    byte key[AES::DEFAULT_KEYLENGTH];


public:
    void GenerateRSAKey(int keyLength, const string privFilename, const string pubFilename, const string seed);
    pair<RSA::PrivateKey, RSA::PublicKey> generateRSAKey(int keyLen, InvertibleRSAFunction &param);

    void GenerateRSAKeyA();
    void GenerateRSAKeyB();


    void SavePublicKey(const string& filename, const PublicKey& key);
    void SavePrivateKey(const string& filename, const PrivateKey& key);
    void Save(const string& filename, const BufferedTransformation& bt);
    void LoadPublicKey(const string& filename,PublicKey& key);
    void Load(const string& filename, BufferedTransformation& bt);

    void SaveHexPrivateKey(const string& filename, const PrivateKey& key);
    void SaveHexPublicKey(const string& filename, const PublicKey& key);
    void SaveHex(const string& filename, const BufferedTransformation& bt);

    string toHexString(const BufferedTransformation& bt);
    string toHexString(const SecByteBlock& bt);
    string toString(const SecByteBlock& bt);

    string getHexHash(string message);
};

#endif // MAINWINDOW_H
