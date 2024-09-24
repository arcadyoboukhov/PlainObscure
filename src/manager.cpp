#include "manager.h"
#include "ui_manager.h"
#include "password.h"
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QDebug>

// Constructor for the Form class
manager::manager(password *pass, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::manager)
    , pass(pass)
{
    ui->setupUi(this);

    connect(ui->goBackButton, &QPushButton::clicked, this, &manager::onGoBackButtonClicked);
    connect(ui->verticalSlider, &QSlider::valueChanged, this, &manager::onSliderValueChanged);
    connect(ui->pushButton_3, &QPushButton::clicked, this, &manager::loadLastSave);

}

void manager::loadLastSave() {
    QByteArray sqlData = pass ? pass->get() : QByteArray(); // Check pass
    if (pass) {
        pass->parseAndInsertData(sqlData);
    } else {
        qDebug() << "pass is null!";
        return; // Early exit if pass is null
    }

    initializeSliderWithContent();
    populateTextEdits();
}


// Function to initialize the slider's range based on the QTextEdit's contents
void manager::initializeSliderWithContent() {
    QList<QTextEdit*> textEdits = findChildren<QTextEdit*>();
    if (!textEdits.isEmpty()) {
        QTextEdit* textEdit = textEdits.first();
        int maximumScroll = textEdit->verticalScrollBar()->maximum();

        ui->verticalSlider->setRange(0, maximumScroll);

        // Initialize the position of the slider to the top
        ui->verticalSlider->setValue(0);
    }
}
QList<UserData> password::retrieveUserData() {
    QList<UserData> users;
    QSqlDatabase db = QSqlDatabase::database();

    if (!db.open()) {
        qDebug() << "Error: Unable to open database.";
        return users;
    }

    QSqlQuery query("SELECT name, username, password FROM Users");
    while (query.next()) {
        QString name = query.value(0).toString();
        QString username = query.value(1).toString();
        QString password = query.value(2).toString();

        users.append({name, username, password});
    }

    db.close();
    return users; // Return the list of users
}





void manager::populateTextEdits() {
    // Clear previous text edits
    QList<QTextEdit*> nameTextEdits;
    QList<QTextEdit*> usernameTextEdits;
    QList<QTextEdit*> passwordTextEdits;

    // Retrieve user data
    QList<UserData> users = pass ? pass->retrieveUserData() : QList<UserData>();

    // Add debug output
    qDebug() << "Found text edits:";
    qDebug() << "Total Users:" << users.size();

    // Loop through user data and find corresponding text edits
    for (int i = 0; i < users.size(); ++i) {
        // Construct the name of the text edits based on the index
        QString nameEditName = QString("nameTextEdit_%1").arg(i);
        QString usernameEditName = QString("usernameTextEdit_%1").arg(i);
        QString passwordEditName = QString("passwordTextEdit_%1").arg(i);

        // Find text edits by constructed names
        QTextEdit* nameTextEdit = findChild<QTextEdit*>(nameEditName);
        QTextEdit* usernameTextEdit = findChild<QTextEdit*>(usernameEditName);
        QTextEdit* passwordTextEdit = findChild<QTextEdit*>(passwordEditName);

        // Populate text edits if they are found
        if (nameTextEdit) {
            nameTextEdit->clear();
            nameTextEdit->append(users[i].name);
        }
        if (usernameTextEdit) {
            usernameTextEdit->clear();
            usernameTextEdit->append(users[i].username);
        }
        if (passwordTextEdit) {
            passwordTextEdit->clear();
            passwordTextEdit->append(users[i].password);
        }
    }

    // Ensure that scrollbars are updated correctly after text is loaded
    for (int i = 0; i < users.size(); ++i) {
        QString nameEditName = QString("nameTextEdit_%1").arg(i);
        QString usernameEditName = QString("usernameTextEdit_%1").arg(i);
        QString passwordEditName = QString("passwordTextEdit_%1").arg(i);

        QTextEdit* nameTextEdit = findChild<QTextEdit*>(nameEditName);
        QTextEdit* usernameTextEdit = findChild<QTextEdit*>(usernameEditName);
        QTextEdit* passwordTextEdit = findChild<QTextEdit*>(passwordEditName);

        if (nameTextEdit) {
            nameTextEdit->verticalScrollBar()->setValue(nameTextEdit->verticalScrollBar()->maximum());
        }
        if (usernameTextEdit) {
            usernameTextEdit->verticalScrollBar()->setValue(usernameTextEdit->verticalScrollBar()->maximum());
        }
        if (passwordTextEdit) {
            passwordTextEdit->verticalScrollBar()->setValue(passwordTextEdit->verticalScrollBar()->maximum());
        }
    }

    // Debugging output if no user data is found
    if (users.isEmpty()) {
        qDebug() << "No user data found.";
    }
}




// Slot for when the slider value changes
void manager::onSliderValueChanged(int value) {
    QList<QTextEdit*> textEdits = findChildren<QTextEdit*>();
    for (QTextEdit* textEdit : textEdits) {
        // Set the scroll value of the QTextEdit
        textEdit->verticalScrollBar()->setValue(value);
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
