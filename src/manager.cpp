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
    connect(ui->verticalSlider, &QSlider::valueChanged, this, &manager::onSliderValueChanged);


    // Initialize the vertical slider
    initializeSliderWithContent();
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
