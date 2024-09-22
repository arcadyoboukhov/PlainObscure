#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class Form;
class password;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

public slots:
    void onSelectImagesButtonClicked(); // Add this line to declare the slot

public:
    Ui::MainWindow *ui;
    Form *formInstance;
    password *passwordInstance;
};

#endif // MAINWINDOW_H
