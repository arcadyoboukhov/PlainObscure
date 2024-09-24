#ifndef PASSWORD_H
#define PASSWORD_H

#include <QWidget>
#include <QSlider>
#include <QLabel>
#include <QPushButton>
#include "mainwindow.h" // Include the MainWindow header
#include <QByteArray>
#include <QImage>
#include <QColor>
#include <iostream>
#include <QString>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QDebug>


struct UserData {
    QString name;
    QString username;
    QString password;
};

using namespace std; // Make std's names available


namespace Ui {
class password;
}

class MainWindow; // Forward declaration
class manager;

class password : public QWidget {
    Q_OBJECT

public:
    explicit password(MainWindow *mainWindow, QWidget *parent = nullptr);
    ~password();


public slots:
    void onGoBackButtonClicked(); // Slot for the Go Back button click
    QString onSelectImagesButtonClicked(QWidget *parent);
    QByteArray compressData(const QByteArray &data);       // Declare compressData method
    QByteArray encryptData(const QByteArray &data, const QByteArray &key);  // Declare encryptData method
    void createDB();
    QByteArray uncompressData(const QByteArray &compressedData);
    QByteArray getDataFromDB();
    QByteArray decryptData(const QByteArray &encryptedData, const QByteArray &key);
public:
    Ui::password *ui;            // Pointer to the UI
    MainWindow *mainWindow;  // Pointer to the MainWindow

    // Method declarations
    QByteArray deriveKeyFromPassword(const QString &password, const QByteArray &salt, int iterations = 1000000, int keyLength = 32);
    QByteArray generateRandomSalt(int length = 32);

    // Declare the pbkdf2_hmac_sha256 method
    QByteArray pbkdf2_hmac_sha256(const QByteArray &password, const QByteArray &salt, int iterations, int keyLength);
    QByteArray combineSaltAndEncryptedData(const QByteArray &salt, const QByteArray &encryptedData);
    std::pair<QByteArray, QByteArray>  extractSaltAndEncryptedData(const QByteArray &combinedData);
    void printDatabaseContents();
    void parseAndInsertData(const QByteArray &data);
    void kill();
    QByteArray get();
    void set(QByteArray passwordDB);
    manager *managerInstance;
    QList<UserData> retrieveUserData();
private:
    std::unique_ptr<QString> masterPassword{ std::make_unique<QString>() }; // Initialize here
    QByteArray salt;
    QByteArray derivedKey;
    // Declare the function here
    QImage embedDataInImage(const QImage& image, const QByteArray& data);
    QByteArray extractDataFromImage(const QImage& image);
    QString QByteArrayToBinaryString(const QByteArray& byteArray);
    QByteArray BinaryStringToQByteArray(const QString& binaryString);
    void fileSelectButton();
    QByteArray uncompressedData;

};

#endif // PASSWORD_H
