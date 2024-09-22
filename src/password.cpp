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
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QDebug>
#include <zlib.h>
#include <QBuffer>
#include <openssl\evp.h>

#include <openssl/rand.h>
#include <iostream>
#include <QImage>
#include <QFile>
#include <QDataStream>
#include <utility>
#include <opencv2/opencv.hpp>
// Or specific modules
#include "C:\opencv\build\include\opencv2/core.hpp"
#include <opencv2/highgui.hpp>
#include <opencv2/imgproc.hpp>

QString filePath;
std::unique_ptr<QString> masterPassword = std::make_unique<QString>();

QByteArray salt;
QByteArray derivedKey;
int value;

using namespace cv;
using namespace std;


// Constructor for the Form class
password::password(MainWindow *mainWindow, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::password)
    , mainWindow(mainWindow)
{
    ui->setupUi(this);
    connect(ui->pushButton, &QPushButton::clicked, this, &password::onGoBackButtonClicked);



}



// On back button clicked
void password::onGoBackButtonClicked() {
    createDB(); // Ensure to check if the database creation succeeded
    *masterPassword  = ui->passwordLineEdit->text();
    QByteArray salt = generateRandomSalt(32); // The salt length is adjustable here
    derivedKey = deriveKeyFromPassword(*masterPassword, salt);
    qDebug() << "derivedkey:" << derivedKey;
    // Hash the derived key once, as it's used multiple times
    QByteArray hashedKey = QCryptographicHash::hash(derivedKey, QCryptographicHash::Sha256);
    value = ui->horizontalSlider->value();


    if (value == 1) {
             qDebug() << "YES -------------------- hidden data.";
        // Extract data from the image

             QImage image(filePath);
            QByteArray extractedData = extractDataFromImage(image);
             // Encode the QByteArray to Base64
             QByteArray base64Data = extractedData.toBase64();

             // Print the Base64 encoded data
            qDebug() << "Extracted Data in Base64:" << base64Data;

            auto result = extractSaltAndEncryptedData(extractedData);
            QByteArray extractedSalt = result.first;
            QByteArray extractedEncryptedData = result.second;

            derivedKey = deriveKeyFromPassword(*masterPassword, extractedSalt);
            hashedKey = QCryptographicHash::hash(derivedKey, QCryptographicHash::Sha256);
            QByteArray decryptedCompressedData = decryptData(extractedEncryptedData, derivedKey);
            QByteArray uncompressedData = uncompressData(decryptedCompressedData);





            } else if (value == 0) {
        qDebug() << "NO -------------------- hidden data.";
                    QByteArray compressedData = compressData(getDataFromDB());
                    QByteArray encryptedCompressedData = encryptData(compressedData, derivedKey);
                    QByteArray combinedData = combineSaltAndEncryptedData(salt, encryptedCompressedData);

                    QImage image(filePath);
                    // Embed data into the image
                    QImage modifiedImage = embedDataInImage(image, combinedData);
                    modifiedImage.save("output.png");

     }
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



QByteArray password::getDataFromDB() {
    QByteArray data;
    QSqlDatabase db = QSqlDatabase::database();

    if (!db.open()) {
        qDebug() << "Error: Unable to open database.";
        return data;
    }

    QSqlQuery query("SELECT name, username, password FROM Users");
    while (query.next()) {
        QString name = query.value(0).toString();
        QString username = query.value(1).toString();
        QString password = query.value(2).toString();

        // Concatenate the data into one QByteArray, converting QString to QByteArray using toUtf8()
        data.append("Name: " + name.toUtf8() + "\n");
        data.append("Username: " + username.toUtf8() + "\n");
        data.append("Password: " + password.toUtf8() + "\n");
    }

    db.close();
    return data;
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




void password::createDB() {
    // Create a connection to the SQLite database
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("user_database.db");

    // Open the database
    if (!db.open()) {
        qDebug() << "Error: Unable to open database.";
        return;
    }


    // Create a SQL query object
    QSqlQuery query;

    // Create a table if it does not already exist
    QString createTableSQL = "CREATE TABLE IF NOT EXISTS Users ("
                             "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                             "name TEXT NOT NULL, "
                             "username TEXT NOT NULL, "
                             "password TEXT NOT NULL);";

    if (!query.exec(createTableSQL)) {
        qDebug() << "Error: Unable to create table." << query.lastError().text();
    } else {
        qDebug() << "Table created successfully.";

        // Insert temporary values into the Users table
        QString insertTempValuesSQL = "INSERT INTO Users (name, username, password) VALUES "
                                      "('John Doe', 'johndoe', 'password123'), "
                                      "('Jane Smith', 'janesmith', 'password456');";

        if (!query.exec(insertTempValuesSQL)) {
            qDebug() << "Error: Unable to insert temporary values." << query.lastError().text();
        } else {
            qDebug() << "Temporary values inserted successfully.";
        }
    }
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


// Function to print contents of the Users table
void printDatabaseContents() {
    QSqlDatabase db = QSqlDatabase::database();

    if (!db.open()) {
        qDebug() << "Error: Unable to open database.";
        return;
    }

    QSqlQuery query("SELECT id, name, username, password FROM Users");
    if (!query.exec()) {
        qDebug() << "Error: Unable to execute query." << query.lastError().text();
        return;
    }

    // Iterate over the results and print each row
    while (query.next()) {
        int id = query.value(0).toInt();
        QString name = query.value(1).toString();
        QString username = query.value(2).toString();
        QString password = query.value(3).toString();

        qDebug() << "ID:" << id
                 << "Name:" << name
                 << "Username:" << username
                 << "Password:" << password;
    }

    db.close();
}











QImage password::embedDataInImage(const QImage &image, const QByteArray &data) {
    QImage resultImage = image.convertToFormat(QImage::Format_ARGB32);  // Ensure consistent format
    int dataSize = data.size();  // Get the size of the data to embed

    // Convert the size of the data into a 32-bit integer (store 4 bytes for size)
    QByteArray sizeBytes(4, 0);  // Reserve 4 bytes for the size header
    sizeBytes[0] = (dataSize >> 24) & 0xFF;
    sizeBytes[1] = (dataSize >> 16) & 0xFF;
    sizeBytes[2] = (dataSize >> 8) & 0xFF;
    sizeBytes[3] = dataSize & 0xFF;

    int totalBits = (dataSize * 8) + (4 * 8);  // Data bits + 32 bits for size
    int bitIndex = 0;

    // Loop through each pixel in the image
    for (int y = 0; y < resultImage.height(); ++y) {
        for (int x = 0; x < resultImage.width(); ++x) {
            if (bitIndex >= totalBits)  // Stop when all bits are embedded
                return resultImage;

            QRgb pixel = resultImage.pixel(x, y);
            uchar red = qRed(pixel);
            uchar green = qGreen(pixel);
            uchar blue = qBlue(pixel);

            // Embed the size first (32 bits)
            int dataByte;
            if (bitIndex < 32) {  // Embed the size in the first 32 bits
                dataByte = sizeBytes[bitIndex / 8];
            } else {  // Embed the actual data after the size
                dataByte = data[(bitIndex - 32) / 8];
            }

            // Check that dataByte exists within bounds
            if ((bitIndex - 32) / 8 < data.size() || bitIndex < 32) {
                int dataBit = (dataByte >> (7 - (bitIndex % 8))) & 1;
                blue = (blue & 0xFE) | dataBit;  // Modify LSB of blue channel
            }

            resultImage.setPixel(x, y, qRgb(red, green, blue));

            ++bitIndex;  // Move to the next bit
        }
    }

    return resultImage;
}



QByteArray password::extractDataFromImage(const QImage &image) {
    QImage formattedImage = image.convertToFormat(QImage::Format_ARGB32);  // Ensure consistent format
    QByteArray extractedData;
    int bitIndex = 0;
    char currentByte = 0;
    int dataSize = 0;

    // First, extract the 32-bit size header (4 bytes)
    for (int y = 0; y < formattedImage.height(); ++y) {
        for (int x = 0; x < formattedImage.width(); ++x) {
            QRgb pixel = formattedImage.pixel(x, y);
            uchar blue = qBlue(pixel);
            int extractedBit = blue & 1;

            currentByte = (currentByte << 1) | extractedBit;

            if (++bitIndex % 8 == 0) {
                if (bitIndex <= 32) {  // Extract size from the first 4 bytes (32 bits)
                    dataSize = (dataSize << 8) | static_cast<uchar>(currentByte);
                    currentByte = 0;  // Reset the byte accumulator
                } else {  // Now extract the actual data
                    if (extractedData.size() < dataSize) {  // Ensure we don't exceed expected size
                        extractedData.append(currentByte);
                    }
                    currentByte = 0;

                    if (extractedData.size() >= dataSize)  // Stop when all data is extracted
                        return extractedData;
                }
            }
        }
    }

    return extractedData;  // Return the extracted data
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




QByteArray readPasswordDatabase(const QString &filePath) {
    QFile file(filePath);
    QByteArray data;

    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&file);
        while (!in.atEnd()) {
            data.append(in.readLine().toUtf8()).append('\n'); // Convert QString to QByteArray
        }
        file.close();
    } else {
        qDebug() << "Could not open file for reading:" << filePath;
    }

    return data.trimmed(); // Return the data without trailing newline
}


password::~password() {
    delete ui;
}
