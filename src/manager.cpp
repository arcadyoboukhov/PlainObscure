#include "manager.h"
#include "ui_manager.h"

// Constructor for the Form class
manager::manager(MainWindow *mainWindow, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::manager)
    , mainWindow(mainWindow)
{
    ui->setupUi(this);

    connect(ui->goBackButton, &QPushButton::clicked, this, &manager::onGoBackButtonClicked);
}

// On back button clicked
void manager::onGoBackButtonClicked() {
    this->hide(); // Hide the settings window
    mainWindow->show(); // Show the main window
}

manager::~manager() {
    delete ui;
}
