#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "form.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    formInstance = new Form(this);

    // Connect signals and slots
    connect(ui->pushButton_2, &QPushButton::clicked, this, &MainWindow::hide);
    connect(ui->pushButton_2, &QPushButton::clicked, formInstance, &Form::show);
}

MainWindow::~MainWindow()
{
    delete ui;
}
