#include "mainwindow.h"
#include <QApplication>
#include <Cryptopp/randpool.h>
#include <Cryptopp/rsa.h>
#include <Cryptopp/hex.h>
#include <Cryptopp/files.h>
#include <Cryptopp/osrng.h>

#pragma comment(lib, "cryptlib.lib")

using namespace std;
using namespace CryptoPP;

//------------------------
// 生成RSA密钥对
//------------------------
void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed)
{
    AutoSeededRandomPool rnd;
    RSA::PrivateKey rsaPrivate;
    rsaPrivate.GenerateRandomWithKeySize(rnd, 3072);
    RSA::PublicKey rsaPublic(rsaPrivate);
}


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();



    return a.exec();
}
