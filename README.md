# SFTP_Client project
###  What is SFTP?
SFTP is the FTP protocol build on top of the SSH protocol.
###  Features:
- Transfer in both directions. **download** and **upload**.
- Transfer **file** and **directory**.
- Auto detection if file or directory.
- The option to transfer **sub-directories**.
- Create the destination directory if not exist.
- If file already exist, re-create it.
- Two authentication methods are available, **password** and **public key**
- Debug mode
### Dependencies
You need to install the Libssh2 library:[web site](https://www.libssh2.org/), [Git page](https://github.com/libssh2/libssh2).
I used those instructions to install this library in windows 10 [How to install](https://github.com/libssh2/libssh2/blob/master/docs/INSTALL_CMAKE).
### How to build.
The project is in c language and to build it use any c complier.
> You may notice i add the openssl library, this is because i have built libssh2 with openssl option enable.
```
gcc -Wall -Wextra -g SFTP_Client.c -I '<path to libssh2>\include' -I '<path to openssl>\include' -L '<path to libssh2>\lib' -L '<path to openssl>\lib' -lssh2 -lws2_32 -lcrypto -lssl -o <file output name>
```
In the source code comment or uncomment this line to enable or disable the debug mode before the compilation.
``
#define LIBSSH2DEBUG
``
###  How to use?
1. Pass the remote SSH ip: -ip <remote SSH ip>
2. Pass the SSH port (22 is the default port number): -port <SSH port>
3. Authentication:
  * Password authentication
    * Pass the username: -u <username>
    * Pass the password: -p <password>
  * Public key method for authentication
    * Pass the username: -u <username>
    * Pass the path to the public key file: -pubk <path to public key>
    * Pass the path to the private key file: -prvk <path to private key>
    * The option to pass the passphrase is exist: -p <passphrase>
4. To upload use: -upload. to download use: -download
5. Pass file/directory to transfer (source path): -s <path to file/diretory>
6. Pass destination path: -d <destination path>
7. Transfer sub-directories: -r
> Note that i included a public key and private key files so you know the format of those files. they don't works, make yours please. use any key generator like putty.
###  Example
 > change the file name to what you used before.
 * SFTP_Client.exe -ip <remote_machine_ip> -u <username> -p <password> -upload -s <source_path_from_your_local_machine> -d <destination_path_to_remote_machine> -r
 * SFTP_Client.exe -ip <remote_machine_ip> -port <port_number> -u <username> -pubk <public_key_path> -prvk <private_key_path> -p <passphrase> -download -s <source_path_from_remote_machine> -d <destination_path_to_local_machine> -r


