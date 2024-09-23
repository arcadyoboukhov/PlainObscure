#ifndef MANAGER_H
#define MANAGER_H

#include <QWidget>
#include <QSlider>
#include <QLabel>
#include <QPushButton>
#include "password.h"

namespace Ui {
class manager;
}

class password; // Forward declaration

class manager : public QWidget {
    Q_OBJECT

public:
    explicit manager(password *pass, QWidget *parent = nullptr);
    ~manager();

public slots:
    void onGoBackButtonClicked(); // Slot for the Go Back button click

public:
    Ui::manager *ui;            // Pointer to the UI
    password *pass;  // Pointer to the MainWindow
    void onSliderValueChanged(int value);
    void initializeSliderWithContent();
};

#endif // FORM_H
