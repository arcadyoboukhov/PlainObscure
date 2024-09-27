# PlainObscure 

![License](https://img.shields.io/badge/license-GNU%20GPL%20v3-blue.svg
) 
PlainObscure is a program that creates, views, and manages password databases. The main feature is its hiding of password databases in large PNG images with LSB. It keeps passwords in JSON which is encrypted with AES-256-CBC encryption (without IVs because I was too busy to make it). The data is also compressed before encryption. So the master password handling uses PBKDF2 with HMAC-SHA256, 32-byte salt, and one million iterations (change the code if too much). 
  

DATA INSERTED ON SETUP IS FAKE!!! 

## Features

- ✅ Hides password DB in PNG photos - With the use of LSB, PlainObscure embeds compressed, encrypted password DB which is stored as a SQL DB. 
- ✅ Standard Security - AES-256-CBC, PBKDF2 with HMAC-SHA256, 32-byte salt, and one million iterations, LSB. 


## Demo

![Demo](https://github.com/arcadyoboukhov/PlainObscure/blob/main/assets/Screenshot%202024-09-24%20074757.png)


## Technologies Used

- **library used:** crypto, internal, opencv2, openssl  
- **Programming Languages:** C++, Cmake
- **Software used:** QT Creator, QT Designer


## Installation

Follow the steps below to install the project locally.

1. Download the program:
   So go on the program and click the Code Button. Click Download Zip.
2. Download QT Creator:
   Go to the QT website (Google it). So, find a YouTube tutorial on how to set it up. I used Mingw, so you will need to set it up with Mingw (not Visual Studio).

3. Select the folder of the project: Select all the files in the project. Run the program in QT Creator. 
 
IT SAVES IMAGES UNDER BUILD!!!