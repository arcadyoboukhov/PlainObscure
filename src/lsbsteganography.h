#ifndef LSBSTEGANOGRAPHY_H
#define LSBSTEGANOGRAPHY_H

#include <QImage>
#include <QString>

class LSBSteganography
{
public:
    LSBSteganography();

    // Embeds the message into the image
    bool embedMessage(QImage &image, const QString &message);

    // Extracts the message from the image
    QString extractMessage(const QImage &image);

private:
    void embedByte(QImage &image, int &x, int &y, char byte);
    char extractByte(const QImage &image, int &x, int &y);

};

#endif // LSBSTEGANOGRAPHY_H
