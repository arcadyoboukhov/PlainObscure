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

    for (int i = 0; i < 18; ++i) {
        QString nameEditName = QString("nameTextEdit_%1").arg(i + 1);
        QString usernameEditName = QString("usernameTextEdit_%1").arg(i + 1);
        QString passwordEditName = QString("passwordTextEdit_%1").arg(i + 1);

        //  QLineEdit pointers
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
    QByteArray jsonData = jsonDoc.toJson(QJsonDocument::Compact); 

    QString formattedJson = QString::fromUtf8(jsonData);

    qDebug() << "Formatted JSON data:" << formattedJson;


    pass->save(formattedJson); 
}




void manager::loadLastSave() {
    
    QByteArray jsonData = pass->get();

    
    QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonData);
    if (jsonDoc.isNull() || !jsonDoc.isArray()) {
        qDebug() << "Failed to parse JSON data or not an array.";
        return; 
    }

    QJsonArray jsonArray = jsonDoc.array();

    
    for (int i = 0; i < jsonArray.size() && i < 18; ++i) {
        QJsonObject jsonObj = jsonArray[i].toObject();

        // Extract values from the JSON object
        QString name = jsonObj["name"].toString();
        QString username = jsonObj["username"].toString();
        QString password = jsonObj["password"].toString();

        // Set the names of the QLineEdit objects
        QString nameEditName = QString("nameTextEdit_%1").arg(i + 1);
        QString usernameEditName = QString("usernameTextEdit_%1").arg(i + 1);
        QString passwordEditName = QString("passwordTextEdit_%1").arg(i + 1);

        //  QLineEdit pointers
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
