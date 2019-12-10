# SFTP_Client project
###  What is SFTP?
SFTP is the FTP protocol build on top of the SSH protocol.
###  Features:
- Transfer in both directions. **download** and **upload**.
- Transfer **file** and **directory**.
- The option to transfer **sub-directories**.
- Create the destination directory if not exist.
- If file already exist, re-create it.
- Two authentication methods are available, **password** and **public key**
### Dependencies
You need to install the Libssh2 library:[web site](https://www.libssh2.org/), [Git page](https://github.com/libssh2/libssh2).
I used those instructions to install this library in windows 10 [How to install](https://github.com/libssh2/libssh2/blob/master/docs/INSTALL_CMAKE).
### How to build.
The project is in c language and to build it use any c complier.
-You may notice i add the openssl library, this is because i build libssh2 with openssl option enable.
```
gcc -Wall -Wextra -g SFTP_Client.c -I '<path to libssh2>\include' -I '<path to openssl>\include' -L '<path to libssh2>\lib' -L '<path to openssl>\lib' -lssh2 -lws2_32 -lcrypto -lssl -o <file output name>
```
###  How to use?
1. use ---

