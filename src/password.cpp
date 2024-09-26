#include "password.h"
#include "ui_password.h"
#include <QFileDialog>
#include <QStringList>
#include <QDebug>
#include <QCoreApplication>
#include <QFile>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QDebug>
#include <QByteArray>
#include <QRandomGenerator>
#include <memory>
#include <QDataStream>
#include <cassert>
#include <QDebug>
#include <zlib.h>
#include <QBuffer>
#include <openssl\evp.h>
#include "lsbsteganography.h"
#include <openssl/rand.h>
#include <iostream>
#include <QImage>
#include <QFile>
#include <QDataStream>
#include <utility>
#include <QFileInfo>
#include <opencv2/opencv.hpp>
#include <QJsonObject>
#include <QJsonArray>


// Or specific modules
#include <opencv2/core.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/imgproc.hpp>
#include "manager.h"


using namespace cv;
using namespace std;
LSBSteganography lsb;


// Static member definitions
QString password::filePath;
std::unique_ptr<QString> password::masterPassword = std::make_unique<QString>();
QByteArray password::salt;
QByteArray password::derivedKey;
int password::value = 0;

// Constructor for the Form class
password::password(MainWindow *mainWindow, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::password)
    , mainWindow(mainWindow)
{
    ui->setupUi(this);
    managerInstance = new manager(this);



    connect(ui->managerButton, &QPushButton::clicked, this, &password::onGoBackButtonClicked);

    connect(ui->pushButton_2, &QPushButton::clicked, this, &password::fileSelectButton);



}



// Function to get the file name from a given file path
QString getFileNameFromFilePath(const QString &filePath) {
    QFileInfo fileInfo(filePath);
    return fileInfo.fileName(); // This will return just the name of the file
}

// On back button clicked
void password::onGoBackButtonClicked() {
    createDB(); // Ensure to check if the database creation succeeded
    *masterPassword  = ui->passwordLineEdit->text();
    value = ui->horizontalSlider->value();

    QImage image(filePath);
    if (value == 1) {
        qDebug() << "YES -------------------- hidden data.";

        // Extract data from the image
        QString extractedMessage = lsb.extractMessage(image);
        QByteArray reconstructedData = BinaryStringToQByteArray(extractedMessage);

        auto result = extractSaltAndEncryptedData(reconstructedData);
        QByteArray extractedSalt = result.first;
        QByteArray extractedEncryptedData = result.second;

        derivedKey = deriveKeyFromPassword(*masterPassword, extractedSalt);
        QByteArray decryptedCompressedData = decryptData(extractedEncryptedData, derivedKey);
        QByteArray uncompressedData = uncompressData(decryptedCompressedData);

        // Call the function to parse and insert data into the in-memory structure
        // parseAndInsertData(uncompressedData);

    } else if (value == 0) {
        qDebug() << "NO -------------------- hidden data.";

        QByteArray salt = generateRandomSalt(32); // The salt length is adjustable here
        qDebug() << "Salt (Hex):" << salt.toHex();
        derivedKey = deriveKeyFromPassword(*masterPassword, salt);
        qDebug() << "derivedkey:" << derivedKey;
        // Hash the derived key once, as it's used multiple times
        QByteArray hashedKey = QCryptographicHash::hash(derivedKey, QCryptographicHash::Sha256);


        QByteArray compressedData = compressData(jsonDocument.toJson(QJsonDocument::Compact)); // Correct
        qDebug() << "json data:" << jsonDocument.toJson(QJsonDocument::Compact);
        QByteArray encryptedCompressedData = encryptData(compressedData, derivedKey);
        qDebug() << "Extracted data (Hex):" << encryptedCompressedData.toHex();
        QByteArray combinedData = combineSaltAndEncryptedData(salt, encryptedCompressedData);
        qDebug() << "combined data:" << combinedData;
        QString binaryString = QByteArrayToBinaryString(combinedData);

        if (lsb.embedMessage(image, binaryString)) {
            // Save the image as embedded_image.png (optional or implement as per requirement)
            image.save("embedded_image.png");
            qDebug() << "Message embedded successfully!";
        } else {
            qDebug() << "Failed to embed message.";
        }
    }

    this->hide();
    managerInstance->show();
}

// File select button implementation
void password::fileSelectButton() {
    // Define the file type filters for JPEG and PNG
    QStringList filters;
    filters << "Images (*.jpeg *.jpg *.png)";

    // Open the file dialog and get the selected file path
    QString fileName = QFileDialog::getOpenFileName(this, "Select Image", "", filters.join(";;"));

    if (!fileName.isEmpty()) {
        filePath = fileName;
        qDebug() << "Selected file:" << filePath; // Log the selected file path
    } else {
        qDebug() << "No file selected."; // Handle the case where user cancels the dialog
    }
}

// 18 Placeholder records
QList<QJsonObject> placeholderData = {
    {{"name", "Alice Smith"}, {"username", "alice.s"}, {"password", "Password123!"}},
    {{"name", "Bob Johnson"}, {"username", "bobby.j"}, {"password", "HelloWorld1!"}},
    {{"name", "Charlie Brown"}, {"username", "charlie.b"}, {"password", "CharliePassword!"}},
    {{"name", "Dana White"}, {"username", "dana.white"}, {"password", "Qwerty12345!"}},
    {{"name", "Eva Green"}, {"username", "eva.green"}, {"password", "GreenLight01!"}},
    {{"name", "Frank Black"}, {"username", "frankblack"}, {"password", "MySuperSecret!"}},
    {{"name", "Gary Oak"}, {"username", "gary.oak"}, {"password", "Pikachu2023!"}},
    {{"name", "Hannah Montana"}, {"username", "hannah.m"}, {"password", "Party123456!"}},
    {{"name", "Ian Malcolm"}, {"username", "ian.m"}, {"password", "JurassicPark2024!"}},
    {{"name", "Jamie Lannister"}, {"username", "jamie.l"}, {"password", "Kingslayer99!"}},
    {{"name", "Karen Hill"}, {"username", "karen.h"}, {"password", "GoldenGirl88!"}},
    {{"name", "Leo Messi"}, {"username", "leo.m"}, {"password", "GoalMachine2023!"}},
    {{"name", "Mona Lisa"}, {"username", "mona.l"}, {"password", "ArtLover101!"}},
    {{"name", "Nina Simone"}, {"username", "nina.s"}, {"password", "JazzLegend02!"}},
    {{"name", "Oscar Wilde"}, {"username", "oscar.w"}, {"password", "WriteMore2019!"}},
    {{"name", "Peter Parker"}, {"username", "peter.p"}, {"password", "SpiderWeb123!"}},
    {{"name", "Quincy Adams"}, {"username", "quincy.a"}, {"password", "HistoryRocks99!"}},
    {{"name", "Rachel Green"}, {"username", "rachel.g"}, {"password", "FriendsForever!"}},
    {{"name", "Samwise Gamgee"}, {"username", "sam.g"}, {"password", "HobbitLife2024!"}},
    };



void password::createDB() {
    // Create an empty JSON array
    QJsonArray jsonArray;

    // Add each item from the placeholder data to the JSON array
    for (const auto& user : placeholderData) {
        jsonArray.append(user);
    }

    // Create a QJsonDocument to hold the JSON array
    jsonDocument = QJsonDocument(jsonArray); // Assign JSON data to the class variable

    // Optionally, you can print the JSON to the console
    qDebug() << jsonDocument.toJson(QJsonDocument::Compact);
}



// Return the file path that is stored in the class
QString password::getFilePath() {
    return filePath; // Assuming filePath is a member variable
}

// Assuming lsb is an instance of the LSBSteganography class
LSBSteganography password::getLsb() {
    return lsb;
}

QString password::QByteArrayToBinaryString(const QByteArray& byteArray) {
    QString binaryString;
    for (char byte : byteArray) {
        for (int i = 7; i >= 0; --i) {
            binaryString.append((byte & (1 << i)) ? '1' : '0');
        }
    }
    return binaryString;
}

QByteArray password::BinaryStringToQByteArray(const QString& binaryString) {
    QByteArray byteArray;
    for (int i = 0; i < binaryString.length(); i += 8) {
        if (i + 7 < binaryString.length()) {
            QString byteString = binaryString.mid(i, 8);
            bool ok;
            char byte = byteString.toInt(&ok, 2); // Convert from binary (base 2)
            if (ok) {
                byteArray.append(byte);
            }
        }
    }
    return byteArray;
}
    // this->hide(); // Hide the settings window
       // mainWindow->show(); // Show the main window

// Function to select only one JPEG or PNG image
QString password::onSelectImagesButtonClicked(QWidget *parent) {
    // Define the file type filters for JPEG and PNG
    QStringList filters;
    filters << "Images (*.jpeg *.jpg *.png)";

    // Open the file dialog and get the selected file path
    filePath = QFileDialog::getOpenFileName(
        parent,
        "Select Image",
        "",
        filters.join(";;") // Use ";;" to separate filters in the dialog
        );

    // Return the selected file path
    return filePath;
}







// Function to derive a cryptographic key using PBKDF2
QByteArray password::deriveKeyFromPassword(const QString &password, const QByteArray &salt, int iterations, int keyLength) {
    return pbkdf2_hmac_sha256(password.toUtf8(), salt, iterations, keyLength);
}

// PBKDF2 implementation
QByteArray password::pbkdf2_hmac_sha256(const QByteArray &password, const QByteArray &salt, int iterations, int keyLength) {
    if (keyLength <= 0 || iterations <= 0) {
        return QByteArray(); // Invalid parameters
    }

    QByteArray derivedKey;
    int blocks = (keyLength + 64 - 1) / 64;
    for (int i = 1; i <= blocks; i++) {
        QByteArray block;
        QByteArray blockSalt = salt + QByteArray::number(i);
        block = QCryptographicHash::hash(blockSalt, QCryptographicHash::Sha512); // Initial block with salt and block index



        QByteArray U = block; // U is initially the same as the block

        // Apply the HMAC iteratively
        for (int j = 1; j < iterations; j++) {
            U = QCryptographicHash::hash(U + password, QCryptographicHash::Sha512);

            // Extend block if necessary
            if (block.size() < U.size()) {
                block.resize(U.size());
            }

            // Perform XOR manually
            for (int k = 0; k < block.size(); ++k) {
                if (k < U.size()) {
                    block[k] ^= U[k]; // XOR each byte
                }
            }
        }
        derivedKey.append(block);
        if (derivedKey.size() >= keyLength) {
            break; // Exit if we've generated enough key data
        }
    }

    return derivedKey.left(keyLength); // Return the derived key truncated to keyLength
}


QByteArray password::compressData(const QByteArray &data) {
    QByteArray compressedData;
    uLong compressedSize = compressBound(data.size());
    compressedData.resize(compressedSize);

    if (compress((Bytef*)compressedData.data(), &compressedSize, (const Bytef*)data.data(), data.size()) == Z_OK) {
        compressedData.resize(compressedSize);
    } else {
        compressedData.clear();  // Compression failed
    }

    return compressedData;
}




QByteArray password::generateRandomSalt(int length) {
    if (length <= 0) {
        return QByteArray(); // Return an empty QByteArray if the length is invalid
    }
    QByteArray salt(length, 0);
    for (int i = 0; i < length; ++i) {
        salt[i] = static_cast<char>(QRandomGenerator::global()->generate() % 512);
    }
    return salt; // Return the salt as a QByteArray
}





QByteArray password::encryptData(const QByteArray &data, const QByteArray &key) {
    QByteArray encryptedData;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx) {
        int len;
        int ciphertextLen;

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.constData(), NULL) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return QByteArray();  // Encryption initialization failed
        }

        const int AES_BLOCK_SIZE = 16;
        encryptedData.resize(data.size() + AES_BLOCK_SIZE);
        if (EVP_EncryptUpdate(ctx, (unsigned char*)encryptedData.data(), &len, (const unsigned char*)data.constData(), data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return QByteArray();  // Encryption update failed
        }
        ciphertextLen = len;

        if (EVP_EncryptFinal_ex(ctx, (unsigned char*)encryptedData.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return QByteArray();  // Encryption finalization failed
        }
        ciphertextLen += len;
        encryptedData.resize(ciphertextLen);

        EVP_CIPHER_CTX_free(ctx);
        // Print as hexadecimal
        std::cout << "Encrypted Data (Hex): " << encryptedData.toHex().toStdString() << std::endl;

        // Print as Base64
        std::cout << "Encrypted Data (Base64): " << encryptedData.toBase64().toStdString() << std::endl;
    }

    return encryptedData;
}

QByteArray password::uncompressData(const QByteArray &compressedData) {
    QByteArray uncompressedData;
    uLongf uncompressedSize = compressedData.size() * 4;  // Estimate an initial size for uncompressed data
    uncompressedData.resize(uncompressedSize);

    // Uncompress the data
    int result = uncompress((Bytef*)uncompressedData.data(), &uncompressedSize, (const Bytef*)compressedData.data(), compressedData.size());

    if (result == Z_OK) {
        uncompressedData.resize(uncompressedSize);  // Resize to the actual uncompressed size
    } else {
        uncompressedData.clear();  // Uncompression failed
    }

    return uncompressedData;
}


QByteArray password::decryptData(const QByteArray &encryptedData, const QByteArray &key) {
    QByteArray decryptedData;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx) {
        int len;
        int plaintextLen;

        // Initialize the decryption operation
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.constData(), NULL) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return QByteArray();  // Decryption initialization failed
        }

        // Resize the decryptedData buffer to be able to hold the decrypted data
        decryptedData.resize(encryptedData.size());

        // Provide the message to be decrypted, and obtain the decrypted output
        if (EVP_DecryptUpdate(ctx, (unsigned char*)decryptedData.data(), &len, (const unsigned char*)encryptedData.constData(), encryptedData.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return QByteArray();  // Decryption update failed
        }
        plaintextLen = len;

        // Finalize the decryption
        if (EVP_DecryptFinal_ex(ctx, (unsigned char*)decryptedData.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return QByteArray();  // Decryption finalization failed
        }
        plaintextLen += len;

        // Resize the decrypted data to the actual size of the plaintext
        decryptedData.resize(plaintextLen);

        // Clean up
        EVP_CIPHER_CTX_free(ctx);
    }

    return decryptedData;
}


void password::save(QString formattedJson) {
    QImage image(filePath);

    // Step 1: Extract existing data
    QString extractedMessage = lsb.extractMessage(image);
    QByteArray reconstructedData = BinaryStringToQByteArray(extractedMessage);

    // Check that we can extract the data properly
    if (reconstructedData.isEmpty()) {
        qWarning() << "No existing data found in the image. Will create a new entry.";
    }

    // Step 2: Extract salt and encrypted data if there's existing data
    QByteArray existingSalt, existingEncryptedData;
    if (!reconstructedData.isEmpty()) {
        auto result = extractSaltAndEncryptedData(reconstructedData);
        existingSalt = result.first;
        existingEncryptedData = result.second;
    }

    // Step 3: Combine new data with existing data
    // Here you want to load the existing JSON data
    QJsonDocument existingDoc = QJsonDocument::fromJson(existingEncryptedData); // Assuming previous data is stored as such
    QJsonArray existingArray = existingDoc.isArray() ? existingDoc.array() : QJsonArray();

    // Step 4: Create a new JSON object from the formatted input
    QJsonDocument newDoc = QJsonDocument::fromJson(formattedJson.toUtf8());
    if (newDoc.isArray()) {
        QJsonArray newArray = newDoc.array();

        // Merge arrays (existing and new)
        for (const QJsonValue &value : newArray) {
            existingArray.append(value);
        }
    }

    // Step 5: Serialize the combined JSON array back to a QByteArray
    QByteArray combinedJsonData = QJsonDocument(existingArray).toJson(QJsonDocument::Compact);

    // Step 6: Compress and encrypt the new combined JSON data
    QByteArray compressedData = compressData(combinedJsonData); // Compress the new combined data
    QByteArray encryptedCompressedData = encryptData(compressedData, derivedKey);

    // Step 7: Combine the salt (if existing) and the new encrypted data
    QByteArray combinedData = combineSaltAndEncryptedData(existingSalt.isEmpty() ? generateRandomSalt(32) : existingSalt,
                                                          encryptedCompressedData);

    // Step 8: Convert combined data to binary string and embed
    QString binaryString = QByteArrayToBinaryString(combinedData);
    if (lsb.embedMessage(image, binaryString)) {
        image.save("updated_embedded_image.png"); // Save with a new name or overwrite if needed
        qDebug() << "Updated embedded message successfully!";
    } else {
        qDebug() << "Failed to update embedded message.";
    }
}








void password::set(QByteArray passwordDB)
{
    QImage image(filePath);
    QByteArray compressedData = passwordDB;
    QByteArray encryptedCompressedData = encryptData(compressedData, derivedKey);
    QByteArray combinedData = combineSaltAndEncryptedData(salt, encryptedCompressedData);

    QString binaryString = QByteArrayToBinaryString(combinedData);
    qDebug() << "Binary String:" << binaryString;

    qDebug() << "data string ::::"<< binaryString;
    // Embed a message
    QString message = binaryString;
    if (lsb.embedMessage(image, message)) {
        image.save("embedded_image.png");
        qDebug() << "Message embedded successfully!";
    } else {
        qDebug() << "Failed to embed message.";
    }

}



QByteArray password::get() {




    QImage image(filePath);

    QString extractedMessage = lsb.extractMessage(image);
    QByteArray reconstructedData = BinaryStringToQByteArray(extractedMessage);
    qDebug() << "combined data:" << reconstructedData;
    auto result = extractSaltAndEncryptedData(reconstructedData);
    QByteArray extractedSalt = result.first;
    QByteArray extractedEncryptedData = result.second;

    derivedKey = deriveKeyFromPassword(*masterPassword, extractedSalt);

    qDebug() << "derivedkey:" << derivedKey;
    QByteArray decryptedCompressedData = decryptData(extractedEncryptedData, derivedKey);
    QByteArray uncompressedData = uncompressData(decryptedCompressedData);
    qDebug() << "uncompressedData:" << uncompressedData;
    return uncompressedData;
}



void password::kill() {
    // Reset all member variables to their initial state
    filePath.clear();
    masterPassword->clear();
    salt.clear();
    derivedKey.clear();
    value = 0;



    // Clear the image data, if any (This depends on how your class is structured)
    // For example: image.reset(); if image was stored as a smart pointer
}











QByteArray password::combineSaltAndEncryptedData(const QByteArray &salt, const QByteArray &encryptedData) {
    QByteArray combinedData;
    QDataStream stream(&combinedData, QIODevice::WriteOnly);

    // Write the size of the salt
    stream << static_cast<qint32>(salt.size());  // Use a fixed size for the salt size (e.g., qint32)
    stream.writeRawData(salt.constData(), salt.size());  // Write the salt data
    stream.writeRawData(encryptedData.constData(), encryptedData.size());  // Write the encrypted data

    return combinedData;
}


std::pair<QByteArray, QByteArray> password::extractSaltAndEncryptedData(const QByteArray &combinedData) {
    QByteArray salt;
    QByteArray encryptedData;

    QDataStream stream(combinedData);

    // Read the salt size
    qint32 saltSize = 0;
    stream >> saltSize;

    // Validate salt size and combined data
    if (saltSize <= 0 || saltSize + sizeof(qint32) > combinedData.size()) {
        qWarning() << "Combined data is too small or invalid to extract salt and encrypted data.";
        return std::make_pair(QByteArray(), QByteArray());  // Return empty pair
    }

    // Read the salt
    salt.resize(saltSize);
    if (stream.readRawData(salt.data(), saltSize) != saltSize) {
        qWarning() << "Failed to read the full salt data.";
        return std::make_pair(QByteArray(), QByteArray());  // Return empty pair
    }

    // Read the remaining encrypted data
    encryptedData.resize(combinedData.size() - sizeof(qint32) - saltSize);
    if (stream.readRawData(encryptedData.data(), encryptedData.size()) != encryptedData.size()) {
        qWarning() << "Failed to read the full encrypted data.";
        return std::make_pair(QByteArray(), QByteArray());  // Return empty pair
    }

    // Debugging output
    qDebug() << "Extracted Salt (Hex):" << salt.toHex();
    qDebug() << "Extracted Encrypted Data (Hex):" << encryptedData.toHex();

    return std::make_pair(salt, encryptedData);
}




password::~password() {
    delete ui;
}
