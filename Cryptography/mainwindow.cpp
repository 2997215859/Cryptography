#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QTextStream>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    digestModeGroup = new QButtonGroup(this);
    digestModeGroup->addButton(ui->radioButton_sha1, MODE_DIGEST_SHA1);
    digestModeGroup->addButton(ui->radioButton_md5, MODE_DIGEST_MD5);
    ui->radioButton_sha1->setChecked(true);

    encryptModeGroup = new QButtonGroup(this);
    encryptModeGroup->addButton(ui->radioButton_aes, MODE_ENCRYPT_AES);
    encryptModeGroup->addButton(ui->radioButton_des, MODE_ENCRYPT_DES);
    ui->radioButton_aes->setChecked(true);

    on_pushButton_gen_a_clicked();
    on_pushButton_gen_b_clicked();
    on_pushButton_gen_k_clicked();
    ui->textEdit_message->setText("Just Test This System");
    ui->textEdit_a_pr->setReadOnly(true);
    ui->textEdit_a_pu->setReadOnly(true);
    ui->textEdit_b_pr->setReadOnly(true);
    ui->textEdit_b_pu->setReadOnly(true);
    ui->textEdit_k->setReadOnly(true);
}

MainWindow::~MainWindow()
{
    delete ui;
    delete digestModeGroup;
    delete encryptModeGroup;
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
    if (digestModeGroup->checkedId() == MODE_DIGEST_SHA1) {
        string s1;
        SHA1 sha1;

        HashFilter f1(sha1, new HexEncoder(new StringSink(s1)));

        ChannelSwitch cs;
        cs.AddDefaultRoute(f1);

        StringSource ss(message, true /*pumpAll*/, new Redirector(cs));
        cout << "SHA-1: " << s1 << endl;
        return s1;
    } else if (digestModeGroup->checkedId() == MODE_DIGEST_MD5) {
        string digest;
        Weak1::MD5 md5;
        StringSource(message, true,
                     new HashFilter(md5, new HexEncoder(new StringSink(digest))));
        cout << "md5: " << digest << endl;
        return digest;
    }
}

void MainWindow::on_pushButton_crypto_clicked()
{

    /**
    ** First part: encryption
    */

    cout << "encrypt start..." << endl;

    AutoSeededRandomPool prng;

    cipher.clear();
    encryptedKey.clear();

    string message = ui->textEdit_message->toPlainText().toStdString();
    msgLen = message.size();
    cout << "msgLen: " << msgLen << endl;
    cout << "message: " << message << endl;

    ////////////////////////////////////////////////
    // digest
    string digest = getHexHash(message);
    ui->textEdit_digest->setText(digest.c_str());

    ////////////////////////////////////////////////
    // signature
    string signature;
    RSASS<PSSR, SHA1>::Signer signer(keyPairA.first);
    {
        StringSource ss1(digest, true,
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
    cout << "plain len: " << plain.size() << endl;

    if (encryptModeGroup->checkedId() == MODE_ENCRYPT_AES) {
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
    } else if (encryptModeGroup->checkedId() == MODE_ENCRYPT_DES) {
        try
        {
            ECB_Mode< DES_EDE2 >::Encryption e;
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
    }
    ////////////////////////////////////////////////
    // encrypt plain text by AES and get the cipher
    ui->textEdit_ciphertext->setText(toHexString(cipher).c_str());

    ///////////////////////////////////////////////
    // Encrypt the symmetric key K with the public key of B
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
    cout << "cipher len: " << cipher.size() << endl;
    cout << "encryptedKey len: " << encryptedKey.size() << endl;
    cout << "encrypt end" << endl << endl;
}

void MainWindow::on_pushButton_decrypto_clicked()
{

    cout << "decrypt start..." << endl;
    /**
    ** Second part: decryption
    */

    AutoSeededRandomPool prng;

    ////////////////////////////////////////////////
    // Decrypt to get the symmetric key K with the private key of B
    byte recoveredKey[AES::DEFAULT_KEYLENGTH];
    string recoveredKeyStr;
    {
        RSAES_OAEP_SHA_Decryptor d(keyPairB.first);
        StringSource ss2( encryptedKey, true,
            new PK_DecryptorFilter( prng, d,
                new StringSink(recoveredKeyStr)
            ) // PK_DecryptorFilter
         ); // StringSource
        strncpy((char*)recoveredKey,recoveredKeyStr.c_str(),recoveredKeyStr.length());
    }
    ui->textEdit_recoveredKey->setText(toHexString(recoveredKeyStr).c_str());

    string recoveredPlain;
    string recoveredMsg;
    string recoveredSignature;
    ////////////////////////////////////////////////
    // Decrypt to get the message and encrypted digest with symmetric key K
    if (encryptModeGroup->checkedId() == MODE_ENCRYPT_AES) {
        try
        {
            ECB_Mode< AES >::Decryption d;
            d.SetKey(recoveredKey, sizeof(recoveredKey));

            // The StreamTransformationFilter removes
            //  padding as required.
            StringSource s(cipher, true,
                new StreamTransformationFilter(d,
                    new StringSink(recoveredPlain)
                ) // StreamTransformationFilter
            ); // StringSource
        }
        catch(const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            exit(1);
        }
    } else if (encryptModeGroup->checkedId() == MODE_ENCRYPT_DES) {
        try
        {
            ECB_Mode< DES_EDE2 >::Decryption d;
            d.SetKey(recoveredKey, sizeof(recoveredKey));

            // The StreamTransformationFilter removes
            //  padding as required.
            StringSource s(cipher, true,
                new StreamTransformationFilter(d,
                    new StringSink(recoveredPlain)
                ) // StreamTransformationFilter
            ); // StringSource
        }
        catch(const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            exit(1);
        }
    }

    recoveredMsg = recoveredPlain.substr(0, msgLen);
    recoveredSignature = recoveredPlain.substr(msgLen);
    cout << "recoveredPlain len " << recoveredPlain.size() << endl;
    cout << "recoveredMsg: " << recoveredMsg << endl;

    ui->textEdit_recoveredMessage->setText(recoveredMsg.c_str());
    ui->textEdit_recoveredSignature->setText(toHexString(recoveredSignature).c_str());
    ui->textEdit_recaculatedDigest->setText(getHexHash(recoveredMsg).c_str());

    ////////////////////////////////////////////////
    // Verify and Recover Signature
    RSASS<PSSR, SHA1>::Verifier verifier(keyPairA.second);
    string recoveredDigest;
    {
        StringSource ss2(recoveredSignature, true,
            new SignatureVerificationFilter(
                verifier,
                new StringSink(recoveredDigest),
                SignatureVerificationFilter::THROW_EXCEPTION | SignatureVerificationFilter::PUT_MESSAGE
           ) // SignatureVerificationFilter
        ); // StringSource
    }
    cout << "Verified signature on message" << endl;
    cout << "recovered digest: " << recoveredDigest << endl;
    ui->textEdit_recoveredDigest->setText(recoveredDigest.c_str());

    cout << "decrypt end..." << endl;
}
