#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "form.h"
#include "password.h"
#include <QString>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    formInstance = new Form(this);
    passwordInstance = new password(this);


    connect(ui->pushButton, &QPushButton::clicked, this, &MainWindow::onSelectImagesButtonClicked);



    // Connect signals and slots
    connect(ui->pushButton_2, &QPushButton::clicked, this, &MainWindow::hide);
    connect(ui->pushButton_2, &QPushButton::clicked, formInstance, &Form::show);
}

void MainWindow::onSelectImagesButtonClicked() {
    passwordInstance->show();
    this->hide();
    // If you want to use the password instance's method to select images, you could do the following:
    QString selectedImages = passwordInstance->onSelectImagesButtonClicked(this);

    // If you want to debug and see the selected files:
    qDebug() << "Selected images:" << selectedImages;
}



MainWindow::~MainWindow()
{
    delete formInstance;      // Proper cleanup
    delete passwordInstance;
    delete ui;                // Proper cleanup
    qDebug() << "MainWindow destructor called";
}
