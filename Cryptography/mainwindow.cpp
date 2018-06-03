#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QTextStream>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_gen_a_clicked()
{
    GenerateRSAKeyA();
}

void MainWindow::GenerateRSAKey(int keyLength, const std::string privFilename, const std::string pubFilename, const std::string seed) {
        using namespace CryptoPP;
        RandomPool randPool;
        randPool.IncorporateEntropy((byte *)seed.c_str(), seed.size());

        RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
        HexEncoder privFile(new FileSink(privFilename.c_str()));
        priv.AccessMaterial().Save(privFile);
        privFile.MessageEnd();

        RSAES_OAEP_SHA_Encryptor pub(priv);
        HexEncoder pubFile(new FileSink(pubFilename.c_str()));
        pub.AccessMaterial().Save(pubFile);
        pubFile.MessageEnd();
}

void MainWindow::GenerateRSAKeyA(){

    using namespace CryptoPP;
    using namespace std;
    ///////////////////////////////////////
    // Pseudo Random Number Generator
    AutoSeededRandomPool rng;

    ///////////////////////////////////////
    // Generate Parameters
    paramsA.GenerateRandomWithKeySize(rng, 3072);

    ///////////////////////////////////////
    // Generated Parameters
    const Integer& n = paramsA.GetModulus();
    const Integer& p = paramsA.GetPrime1();
    const Integer& q = paramsA.GetPrime2();
    const Integer& d = paramsA.GetPrivateExponent();
    const Integer& e = paramsA.GetPublicExponent();

    ///////////////////////////////////////
    // Dump
    cout << "RSA Parameters:" << endl;
    cout << " n: " << n << endl;
    cout << " p: " << p << endl;
    cout << " q: " << q << endl;
    cout << " d: " << d << endl;
    cout << " e: " << e << endl;
    cout << endl;

    ///////////////////////////////////////
    // Create Keys
    privateKeyA = RSA::PrivateKey(paramsA);
    publicKeyA = RSA::PublicKey(paramsA);

    {
        QString rsaPrivateFilename("rsa-private-a.key");
        SaveHexPrivateKey(rsaPrivateFilename.toStdString(), privateKeyA);
        QFile privateFile(rsaPrivateFilename);
        if (!privateFile.open(QIODevice::ReadOnly | QFile::Text)) {
            QMessageBox::warning(this, "Warning", "Cannot open file: " + privateFile.errorString());
            return;
        }
        QTextStream in(&privateFile);
        QString text = in.readAll();
        ui->textEdit_a_pr->setText(text);
    }

    {
        QString rsaPublicFilename("rsa-public-a.key");
        SaveHexPublicKey(rsaPublicFilename.toStdString(), publicKeyA);
        QFile publicFile(rsaPublicFilename);
        if (!publicFile.open(QIODevice::ReadOnly | QFile::Text)) {
            QMessageBox::warning(this, "Warning", "Cannot open file: " + publicFile.errorString());
            return;
        }
        QTextStream in(&publicFile);
        QString text = in.readAll();
        ui->textEdit_a_pu->setText(text);
    }


}

void MainWindow::SavePublicKey(const std::string& filename, const CryptoPP::PublicKey& key) {
    CryptoPP::ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}

void MainWindow::SavePrivateKey(const std::string& filename, const CryptoPP::PrivateKey& key) {
    CryptoPP::ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}

void MainWindow::Save(const std::string &filename, const CryptoPP::BufferedTransformation &bt) {
    CryptoPP::FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}

void MainWindow::LoadPublicKey(const std::string& filename, CryptoPP::PublicKey& key) {
    using namespace CryptoPP;
    ByteQueue queue;
    Load(filename, queue);

    key.Load(queue);
}
void MainWindow:: Load(const std::string& filename, CryptoPP::BufferedTransformation& bt){
    using namespace CryptoPP;
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}


void MainWindow::SaveHexPrivateKey(const std::string& filename, const CryptoPP::PrivateKey& key){
    using namespace CryptoPP;
    ByteQueue queue;
     key.Save(queue);
     SaveHex(filename, queue);
}

void MainWindow::SaveHexPublicKey(const std::string& filename, const CryptoPP::PublicKey& key){
    using namespace CryptoPP;
    ByteQueue queue;
    key.Save(queue);

    SaveHex(filename, queue);
}

void MainWindow::SaveHex(const std::string& filename, const CryptoPP::BufferedTransformation& bt){
    using namespace CryptoPP;
    HexEncoder encoder;

    bt.CopyTo(encoder);
    encoder.MessageEnd();

    Save(filename, encoder);
}

void MainWindow::on_pushButton_gen_b_clicked()
{
    unsigned int keyLength = 256;
    std::string pubFilename("pub_file.txt");
    std::string privFilename("priv_file.txt");
    std::string thisSeed("2");
    GenerateRSAKeyB();
}

void MainWindow::GenerateRSAKeyB(){

    using namespace CryptoPP;
    using namespace std;
    ///////////////////////////////////////
    // Pseudo Random Number Generator
    AutoSeededRandomPool rng;

    ///////////////////////////////////////
    // Generate Parameters
    paramsB.GenerateRandomWithKeySize(rng, 3072);

    ///////////////////////////////////////
    // Generated Parameters
    const Integer& n = paramsB.GetModulus();
    const Integer& p = paramsB.GetPrime1();
    const Integer& q = paramsB.GetPrime2();
    const Integer& d = paramsB.GetPrivateExponent();
    const Integer& e = paramsB.GetPublicExponent();

    ///////////////////////////////////////
    // Dump
    cout << "RSA Parameters:" << endl;
    cout << " n: " << n << endl;
    cout << " p: " << p << endl;
    cout << " q: " << q << endl;
    cout << " d: " << d << endl;
    cout << " e: " << e << endl;
    cout << endl;

    ///////////////////////////////////////
    // Create Keys
    privateKeyB = RSA::PrivateKey(paramsB);
    publicKeyB = RSA::PublicKey(paramsB);

    {
        QString rsaPrivateFilename("rsa-private-b.key");
        SaveHexPrivateKey(rsaPrivateFilename.toStdString(), privateKeyB);
        QFile privateFile(rsaPrivateFilename);
        if (!privateFile.open(QIODevice::ReadOnly | QFile::Text)) {
            QMessageBox::warning(this, "Warning", "Cannot open file: " + privateFile.errorString());
            return;
        }
        QTextStream in(&privateFile);
        QString text = in.readAll();
        ui->textEdit_b_pr->setText(text);
    }

    {
        QString rsaPublicFilename("rsa-public-b.key");
        SaveHexPublicKey(rsaPublicFilename.toStdString(), privateKeyB);
        QFile publicFile(rsaPublicFilename);
        if (!publicFile.open(QIODevice::ReadOnly | QFile::Text)) {
            QMessageBox::warning(this, "Warning", "Cannot open file: " + publicFile.errorString());
            return;
        }
        QTextStream in(&publicFile);
        QString text = in.readAll();
        ui->textEdit_b_pu->setText(text);
    }
}
