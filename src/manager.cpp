#include "manager.h"
#include "ui_manager.h"

// Constructor for the Form class
manager::manager(password *pass, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::manager)
    , pass(pass)
{
    ui->setupUi(this);

    connect(ui->goBackButton, &QPushButton::clicked, this, &manager::onGoBackButtonClicked);
}

// On back button clicked
void manager::onGoBackButtonClicked() {
    this->hide(); // Hide the settings window
    pass->show(); // Show the main window
}

manager::~manager() {
    delete ui;
}
