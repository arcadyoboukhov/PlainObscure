#include "form.h"
#include "ui_form.h"

// Constructor for the Form class
Form::Form(MainWindow *mainWindow, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Form)
    , mainWindow(mainWindow)
{
    ui->setupUi(this);

    connect(ui->goBackButton, &QPushButton::clicked, this, &Form::onGoBackButtonClicked);
}

// On back button clicked
void Form::onGoBackButtonClicked() {
    this->hide(); // Hide the settings window
    mainWindow->show(); // Show the main window
}

Form::~Form() {
    delete ui;
}
