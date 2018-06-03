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

string MainWindow::toHexString(const string &raw){
    string encoded;
    StringSource(raw, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
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

    /**
    ** First part: encryption
    */

    AutoSeededRandomPool prng;



    string message = "ECB Mode Test";
    string encoded, recovered;

    ////////////////////////////////////////////////
    // digest
    string digest = getHexHash(message);
    ui->textEdit_digest->setText(digest.c_str());

    ////////////////////////////////////////////////
    // signature
    string signature;
    RSASS<PSSR, SHA1>::Signer signer(keyPairA.first);
    {
        StringSource ss1(signature, true,
            new SignerFilter(prng, signer,
                new StringSink(signature),
                true // putMessage for recovery
           ) // SignerFilter
        ); // StringSource
        // generate n bytes's signature, n should equal to the bytes len of rsa mod number, in my program, it's 3072 / 8
        cout << "signature len: " << signature.size() << endl;
    }
    ui->textEdit_signature->setText(toHexString(signature).c_str());

    // plain composed of message and signature, the plain text will be encrypted and then send out
    string plain = message + signature;

    ////////////////////////////////////////////////
    // encrypt plain text by AES and get the cipher
    string cipher;
    try
    {
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
    ui->textEdit_ciphertext->setText(toHexString(cipher).c_str());

    ///////////////////////////////////////////////
    // Encrypt the symmetric key K with the public key of B
    std::string encryptedKey;
//    string keyStr((char*)key, sizeof(key));
    string keyStr("RSA Encryption");
    {
        RSAES_OAEP_SHA_Encryptor e(keyPairB.second);
        StringSource ss1(key, sizeof(key), true,
            new PK_EncryptorFilter( prng, e,
                new StringSink(encryptedKey)
            ) // PK_EncryptorFilter
         ); // StringSource
    }
    ui->textEdit_encryptedKey->setText(toHexString(encryptedKey).c_str());

    ////////////////////////////////////////////////
    // send text
    string sendText = cipher + encryptedKey;

    /**
    ** Second part: decryption
    */

    ////////////////////////////////////////////////
    // Decrypt to get the symmetric key K with the private key of B
    byte recoveredKey[AES::DEFAULT_KEYLENGTH];
    {
        string recovered;
        RSAES_OAEP_SHA_Decryptor d(keyPairB.first);
        StringSource ss2( encryptedKey, true,
            new PK_DecryptorFilter( prng, d,
                new StringSink(recovered)
            ) // PK_DecryptorFilter
         ); // StringSource
        strncpy((char*)recoveredKey,recovered.c_str(),recovered.length());
    }

    string recoveredPlain;
    string recoveredMsg;
    string recoveredSignature;
    ////////////////////////////////////////////////
    // Decrypt to get the message and encrypted digest with symmetric key K
    try
    {
        ECB_Mode< AES >::Decryption d;
        d.SetKey(key, sizeof(key));

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
            new StreamTransformationFilter(d,
                new StringSink(recoveredPlain)
            ) // StreamTransformationFilter
        ); // StringSource

        assert(recoveredPlain == plain);
        recoveredMsg = recoveredPlain.substr(0, recoveredPlain.size() - 3072/8);
        recoveredSignature = recoveredPlain.substr(recoveredPlain.size() - 3072/8 + 1);
        cout << "recoveredMsg: " << recoveredMsg << endl;
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
