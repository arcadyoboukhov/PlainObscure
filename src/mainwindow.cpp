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


    
    connect(ui->pushButton_2, &QPushButton::clicked, this, &MainWindow::hide);
    connect(ui->pushButton_2, &QPushButton::clicked, formInstance, &Form::show);
}

void MainWindow::onSelectImagesButtonClicked() {
    passwordInstance->show();
    this->hide();
    
    QString selectedImages = passwordInstance->onSelectImagesButtonClicked(this);

    
    qDebug() << "Selected images:" << selectedImages;
}



MainWindow::~MainWindow()
{
    delete formInstance;      
    delete passwordInstance;
    delete ui;                
    qDebug() << "MainWindow destructor called";
}
