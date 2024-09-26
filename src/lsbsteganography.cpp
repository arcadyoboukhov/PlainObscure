#include "lsbsteganography.h"
#include <QImage>
#include <QDebug>

LSBSteganography::LSBSteganography() {}

bool LSBSteganography::embedMessage(QImage &image, const QString &message) {
    QByteArray bytes = message.toUtf8();
    int width = image.width();
    int height = image.height();

    if (bytes.size() * 8 > width * height * 3) {
        qDebug() << "Message is too large to fit in the image.";
        return false;
    }

    int x = 0, y = 0;
    for (char byte : bytes) {
        embedByte(image, x, y, byte);
    }

    // Embed end-of-message marker (0x00)
    embedByte(image, x, y, 0x00);

    return true;
}

void LSBSteganography::clearMessage(QImage &image) {
    int width = image.width();
    int height = image.height();

    // Iterate through each pixel
    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
            QColor color = image.pixelColor(x, y);
            int r = color.red() & ~1;  // Clear the LSB of the red channel
            int g = color.green() & ~1; // Clear the LSB of the green channel
            int b = color.blue() & ~1;  // Clear the LSB of the blue channel
            color.setRed(r);
            color.setGreen(g);
            color.setBlue(b);
            image.setPixelColor(x, y, color);  // Set the updated color
        }
    }
}


QString LSBSteganography::extractMessage(const QImage &image) {
    QByteArray bytes;
    int x = 0, y = 0;
    char byte;

    do {
        byte = extractByte(image, x, y);
        if (byte != 0x00) {
            bytes.append(byte);
        }
    } while (byte != 0x00); // Stop at null terminator

    return QString::fromUtf8(bytes);
}

void LSBSteganography::embedByte(QImage &image, int &x, int &y, char byte) {
    for (int i = 0; i < 8; ++i) {
        QRgb pixel = image.pixel(x, y);
        int lsb = (byte >> i) & 1;

        int r = qRed(pixel);
        int g = qGreen(pixel);
        int b = qBlue(pixel);

        // Modify the least significant bit of the red channel
        r = (r & ~1) | lsb;

        // Update the pixel
        image.setPixel(x, y, qRgb(r, g, b));

        // Move to the next pixel
        if (++x >= image.width()) {
            x = 0;
            ++y;
        }
    }
}

char LSBSteganography::extractByte(const QImage &image, int &x, int &y) {
    char byte = 0;
    for (int i = 0; i < 8; ++i) {
        QRgb pixel = image.pixel(x, y);
        int lsb = qRed(pixel) & 1;
        byte |= (lsb << i);

        // Move to the next pixel
        if (++x >= image.width()) {
            x = 0;
            ++y;
        }
    }
    return byte;
}
