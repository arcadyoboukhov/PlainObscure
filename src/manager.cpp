#include "manager.h"
#include "ui_manager.h"
#include "password.h"
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QDebug>
#include <QApplication>
#include <QFileDialog>
#include <QWidget>
#include <QString>
#include <QLineEdit>

// Constructor for the Form class
manager::manager(password *pass, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::manager)
    , pass(pass)
{
    ui->setupUi(this);

    connect(ui->goBackButton, &QPushButton::clicked, this, &manager::onGoBackButtonClicked);
    connect(ui->pushButton_2, &QPushButton::clicked, this, &manager::saveData);
    connect(ui->pushButton_3, &QPushButton::clicked, this, &manager::loadLastSave);

}


void manager::saveData() {
    QJsonArray jsonArray;

    // Loop through the indices to gather data from 1 through 18
    for (int i = 0; i < 18; ++i) {
        QString nameEditName = QString("nameTextEdit_%1").arg(i + 1);
        QString usernameEditName = QString("usernameTextEdit_%1").arg(i + 1);
        QString passwordEditName = QString("passwordTextEdit_%1").arg(i + 1);

        // Find the QLineEdit pointers
        QLineEdit *nameEdit = this->findChild<QLineEdit*>(nameEditName);
        QLineEdit *usernameEdit = this->findChild<QLineEdit*>(usernameEditName);
        QLineEdit *passwordEdit = this->findChild<QLineEdit*>(passwordEditName);

        if (nameEdit && usernameEdit && passwordEdit) {
            QJsonObject jsonObj;
            jsonObj["name"] = nameEdit->text();
            jsonObj["username"] = usernameEdit->text();
            jsonObj["password"] = passwordEdit->text();
            jsonArray.append(jsonObj);
        } else {
            qDebug() << "Some QLineEdit not found for index:" << (i + 1);
        }
    }

    QJsonDocument jsonDoc(jsonArray);
    QByteArray jsonData = jsonDoc.toJson(QJsonDocument::Compact); // Compact format

    // Remove the unnecessary formatting
    QString formattedJson = QString::fromUtf8(jsonData);

    qDebug() << "Formatted JSON data:" << formattedJson;

    // Pass the JSON string to the password class for saving
    pass->save(formattedJson); // Assuming you have a save function to handle storing this
}




void manager::loadLastSave() {
    // Call the method in the password class to get the last saved data
    QByteArray jsonData = pass->get();

    // Parse the JSON data
    QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonData);
    if (jsonDoc.isNull() || !jsonDoc.isArray()) {
        qDebug() << "Failed to parse JSON data or not an array.";
        return; // Optionally show an error message to the user here
    }

    QJsonArray jsonArray = jsonDoc.array();

    // Ensure not overriding more UI elements than available
    for (int i = 0; i < jsonArray.size() && i < 18; ++i) {
        QJsonObject jsonObj = jsonArray[i].toObject();

        // Extract values from the JSON object
        QString name = jsonObj["name"].toString();
        QString username = jsonObj["username"].toString();
        QString password = jsonObj["password"].toString();

        // Set the names of the QLineEdit objects properly
        QString nameEditName = QString("nameTextEdit_%1").arg(i + 1);
        QString usernameEditName = QString("usernameTextEdit_%1").arg(i + 1);
        QString passwordEditName = QString("passwordTextEdit_%1").arg(i + 1);

        // Find the QLineEdit pointers
        QLineEdit *nameEdit = this->findChild<QLineEdit*>(nameEditName);
        QLineEdit *usernameEdit = this->findChild<QLineEdit*>(usernameEditName);
        QLineEdit *passwordEdit = this->findChild<QLineEdit*>(passwordEditName);

        // Set the text fields if they are not null
        if (nameEdit) {
            nameEdit->setText(name);
        } else {
            qDebug() << "Name edit not found:" << nameEditName;
        }
        if (usernameEdit) {
            usernameEdit->setText(username);
        } else {
            qDebug() << "Username edit not found:" << usernameEditName;
        }
        if (passwordEdit) {
            passwordEdit->setText(password);
        } else {
            qDebug() << "Password edit not found:" << passwordEditName;
        }
    }
}








// On back button clicked
void manager::onGoBackButtonClicked() {
    pass->kill();
    this->hide(); // Hide the settings window
    pass->show(); // Show the main window
}

manager::~manager() {
    delete ui;
}
