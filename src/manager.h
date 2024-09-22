#ifndef MANAGER_H
#define MANAGER_H

#include <QWidget>
#include <QSlider>
#include <QLabel>
#include <QPushButton>
#include "mainwindow.h" // Include the MainWindow header
#include "password.h"

namespace Ui {
class manager;
}

class MainWindow; // Forward declaration

class manager : public QWidget {
    Q_OBJECT

public:
    explicit manager(MainWindow *mainWindow, QWidget *parent = nullptr);
    ~manager();

public slots:
    void onGoBackButtonClicked(); // Slot for the Go Back button click

public:
    Ui::manager *ui;            // Pointer to the UI
    MainWindow *mainWindow;  // Pointer to the MainWindow
};

#endif // FORM_H
