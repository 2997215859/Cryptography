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
    HexEncoder encoder;

    bt.CopyTo(encoder);
    encoder.MessageEnd();

    Save(filename, encoder);
}

string MainWindow::toString(const SecByteBlock& bt){
    std::string str(reinterpret_cast<const char*>(bt.data()), bt.size());
    return str;
}

string MainWindow::toHexString(const BufferedTransformation& bt){
    std::string encoded;
    HexEncoder encoder;
    bt.CopyTo(encoder);
    encoder.MessageEnd();

    word64 size = encoder.MaxRetrievable();
    if(size)
    {
        encoded.resize(size);
        encoder.Get((byte*)&encoded[0], encoded.size());
    }
    return encoded;
}

string MainWindow::toHexString(const SecByteBlock& bt){
    std::string encoded;
    HexEncoder encoder;
    encoder.Put(bt, bt.size());
    encoder.MessageEnd();

    word64 size = encoder.MaxRetrievable();
    if(size)
    {
        encoded.resize(size);
        encoder.Get((byte*)&encoded[0], encoded.size());
    }
    return encoded;
}

void MainWindow::on_pushButton_gen_a_clicked()
{
    GenerateRSAKeyA();
}

void MainWindow::on_pushButton_gen_b_clicked()
{
    GenerateRSAKeyB();
}

pair<RSA::PrivateKey, RSA::PublicKey> MainWindow::generateRSAKey(int keyLen, InvertibleRSAFunction &param) {
    AutoSeededRandomPool rng;
    param.GenerateRandomWithKeySize(rng, keyLen);

    ///////////////////////////////////////
    // Generated Parameters
    const Integer& n = param.GetModulus();
    const Integer& p = param.GetPrime1();
    const Integer& q = param.GetPrime2();
    const Integer& d = param.GetPrivateExponent();
    const Integer& e = param.GetPublicExponent();

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
    RSA::PrivateKey privateKey(param);
    RSA::PublicKey publicKey(param);
    return {privateKey, publicKey};
}

void MainWindow::GenerateRSAKeyA(){

    keyPairA = generateRSAKey(3072, paramsA);

    ByteQueue queuePr;
    keyPairA.first.Save(queuePr);
    string hexStrPr = toHexString(queuePr);
    ui->textEdit_a_pr->setText(hexStrPr.c_str());

    ByteQueue queuePu;
    keyPairA.second.Save(queuePu);
    string hexStrPu = toHexString(queuePu);
    ui->textEdit_a_pu->setText(hexStrPu.c_str());
}

void MainWindow::GenerateRSAKeyB(){

    keyPairB = generateRSAKey(3072, paramsB);

    ByteQueue queuePr;
    keyPairB.first.Save(queuePr);
    string hexStrPr = toHexString(queuePr);
    ui->textEdit_b_pr->setText(hexStrPr.c_str());

    ByteQueue queuePu;
    keyPairB.second.Save(queuePu);
    string hexStrPu = toHexString(queuePu);
    ui->textEdit_b_pu->setText(hexStrPu.c_str());

}

void MainWindow::on_pushButton_gen_k_clicked()
{
    AutoSeededRandomPool rnd;

    rnd.GenerateBlock(key,sizeof(key));

    string encoded;
    encoded.clear();
    StringSource(key, sizeof(key), true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    cout << "key: " << encoded << endl;
    ui->textEdit_k->setText(encoded.c_str());
}

string MainWindow::getHexHash(string message){
    string s1;
    SHA1 sha1;

    HashFilter f1(sha1, new HexEncoder(new StringSink(s1)));

    ChannelSwitch cs;
    cs.AddDefaultRoute(f1);

    StringSource ss(message, true /*pumpAll*/, new Redirector(cs));

    cout <<" Message: " << message << endl;
    cout << "SHA-1: " << s1 << endl;
    return s1;
}

void MainWindow::on_pushButton_crypto_clicked()
{

    AutoSeededRandomPool prng;

    prng.GenerateBlock(key, sizeof(key));

    string message = "ECB Mode Test";
    string cipher, encoded, recovered;

    string digest = getHexHash(message);

    ////////////////////////////////////////////////
    // Setup
    string message2 = digest, signature, recovered2;

    ////////////////////////////////////////////////
    // Sign and Encode
    RSASS<PSSR, SHA1>::Signer signer(keyPairA.first);

    StringSource ss1(message2, true,
        new SignerFilter(prng, signer,
            new StringSink(signature),
            true // putMessage for recovery
       ) // SignerFilter
    ); // StringSource

    ////////////////////////////////////////////////
    // Verify and Recover
    RSASS<PSSR, SHA1>::Verifier verifier(keyPairA.second);

    StringSource ss2(signature, true,
        new SignatureVerificationFilter(
            verifier,
            new StringSink(recovered2),
            SignatureVerificationFilter::THROW_EXCEPTION | SignatureVerificationFilter::PUT_MESSAGE
       ) // SignatureVerificationFilter
    ); // StringSource

    cout << "Verified signature on message" << endl;
    cout << "recovered digest: " << recovered2 << endl;

    string plain = message + digest;

    try
    {
        cout << "plain text: " << plain << endl;

        ECB_Mode< AES >::Encryption e;
        e.SetKey(key, sizeof(key));

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(plain, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }




//    /*********************************\
//    \*********************************/

//    // Pretty print
//    encoded.clear();
//    StringSource(cipher, true,
//        new HexEncoder(
//            new StringSink(encoded)
//        ) // HexEncoder
//    ); // StringSource
//    cout << "cipher text: " << encoded << endl;

//    /*********************************\
//    \*********************************/

//    try
//    {
//        ECB_Mode< AES >::Decryption d;
//        d.SetKey(key, sizeof(key));

//        // The StreamTransformationFilter removes
//        //  padding as required.
//        StringSource s(cipher, true,
//            new StreamTransformationFilter(d,
//                new StringSink(recovered)
//            ) // StreamTransformationFilter
//        ); // StringSource

//        cout << "recovered text: " << recovered << endl;
//    }
//    catch(const CryptoPP::Exception& e)
//    {
//        cerr << e.what() << endl;
//        exit(1);
//    }

    /*********************************\
    \*********************************/

}
