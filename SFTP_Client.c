/****
 * 
 * This program will upload and download files from SSH client device to an SSH remote device (server) using the password and the public key method
 * The program options (arguements):
 *      the ssh remote device ip address (-ip <ip>)
 *      the ssh remote device ssh port (-port <port>) (22 is the default port number)
 *      username and password to log in to the SSH remote device (-u <username> -p <password>)
 *      path to public and private key (-pubk <public key path> -prvk <private key path>) (if those arguements was present the password is the passphrase)
 *      the action which is upload (-upload) "default" or download (-download)
 *      no need to use this: the file to download/upload (-f <filename>) or the directory to download/upload (-d <directory>). the name of the file or directory needs to be attached with the full path
 *      the source path (-s <path>)
 *      if the source is a directory, we have the option to recursive through sub-directory (-r)
 *      the destination path (-d <path>)
 * 
 * features:
 *  + transfer files and directories in both directions (upload and download)
 *  + create directory and parents directory in the destination device (SSH client or SSH remote) if it's not exist
 *  + transfer directory with the option of transfering or not the sub directories
 *  + transfer file even the file already exist in the destination device. (rewrite file)
 *  + use the password authentication or public and private key authentication
 * 
 * example:
 *  + .\\SFTP_Client.exe -ip <remote_machine_ip> -u <username> -p <password> -upload -s <source_path_from_your_local_machine> -d <destination_path_to_remote_machine> -r
 *  + .\\SFTP_Client.exe -ip <remote_machine_ip> -port <port_number> -u <username> -pubk <public_key_path> -prvk <private_key_path> -p <passphrase> -download -s <source_path_from_remote_machine> -d <destination_path_to_local_machine> -r
 * 
 * how it works:
 * 1. parse passed arguements (options) to get the remote device ip, username, password, upload or download, etc..
 * 2. prepare tcp/ip socket
 * 3. init the libssh2 functions, it's a global library initialization and it will init the crypto library. (this function use global state and do not use thread safe)
 * 4. create SSH session
 * 5. if debug mode was enbaled then activate the trace function
 * 6. handshake with the remote SSH server to exchange keys, setup the crypto, compression and MAC layers
 * 7. get the available authentication methods from the remote SSH server
 * 8. start authentication. It depends on the one we want to use and the available methods in the remote SSH server (if public key methode was the option then the SSH remote device should have (already know) the public key)
 * 9. establish the SFTP session
 * 10. store all source path (files and directories)
 * 11. create the destination path if not exist
 * 12. transfer files and create directories (upload/download file and directory).
 * 13. close SFTP session, ssh session, SSH2 library, socket
 * 14. exit program
 * 
*****/

#include <libssh2.h>
#include <libssh2_sftp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // for the sleep function
#include <string.h>
#include <sys/stat.h> // this works for me even in windows because i'm using mingw. for other solution use findfirstfile technique
#include <dirent.h> // this works for me even in windows because i'm using mingw. for other solution use findfirstfile technique
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// linux headers is not complited
#elif UNIX || LINUX
#include <sys/stat.h>
#include <dirent.h>
#endif

// enable/disable trace function for debugging 
#define LIBSSH2DEBUG

/*
 * enum represent all options in 3 bits
 * bit 0 for the action (0 for upload or 1 for download)
 * bit 1 and 2 for authentication method (00 for password and 01 for public/private key, 10 and 11 reserved for future use)
 * bit 3 for recursivity (sub directories works only for directory)
 */
enum{
    OPTION_ACTION_MASK = 0b0001,
    OPTION_AUTH_MASK = 0b0110,
    OPTION_REC_MASK = 0b1000,
    OPTION_UPLOAD=0b0000,
    OPTION_DOWNLOAD=0b0001,
    OPTION_AUTH_PUBKEY=0b0000,
    OPTION_AUTH_PASSWORD=0b0010,
    OPTION_REC=0b1000
};
int options = OPTION_UPLOAD|OPTION_AUTH_PASSWORD; // upload and use password auth method
int err;
char *remote_ip; //="192.168.1.110";
int remote_port = 22; // 22 is the default shh port
char *userName; //= "pi";
char *password; //= "raspberry"; // "shadow" (for the pub_key auth method)
char *publicKeyPath; //= "pub_rsa_key.pub";
char *privateKeyPath; //= "private_rsa_key";
#ifdef WIN32
SOCKET mySocket = INVALID_SOCKET;
WSADATA myWSAData;
#endif
struct sockaddr_in remote_sockaddr_in;
LIBSSH2_SESSION *mySession;
char *listAuth;
LIBSSH2_SFTP *sftp_session = NULL;
enum{
    DIRECTORY_TYPE=0b01,
    FILE_TYPE=0b10,
};
typedef struct sourcePath_struct
{
    char *path;
    int type;
    struct sourcePath_struct *nextSourcePath;
}sourcePath_t;
sourcePath_t *listSourcePath=NULL; // linked list of path (table of string)
char *destinationPath; //="/home/pi/Desktop/newDirFromClientSSH"; // one path (string)

// add new source path to the list of source path
void addPathToListSourcePath(char* sourcePath, int sourcePathType){
    printf("add path %s with type %d\n", sourcePath, sourcePathType);
    if(listSourcePath == NULL){
        listSourcePath = (sourcePath_t*)malloc(sizeof(sourcePath_t));
        listSourcePath->path = (char*)calloc(strlen(sourcePath)+1, sizeof(char));
        strcpy(listSourcePath->path, sourcePath);
        listSourcePath->type = sourcePathType;
        listSourcePath->nextSourcePath=NULL;
    }
    else{
        sourcePath_t *lastPath = listSourcePath;
        while(lastPath->nextSourcePath != NULL){
            lastPath = lastPath->nextSourcePath;
        }
        lastPath->nextSourcePath = (sourcePath_t*)malloc(sizeof(sourcePath_t));
        (lastPath->nextSourcePath)->path = (char*)calloc(strlen(sourcePath)+1, sizeof(char));
        strcpy((lastPath->nextSourcePath)->path, sourcePath);
        (lastPath->nextSourcePath)->type = sourcePathType;
        (lastPath->nextSourcePath)->nextSourcePath=NULL;
    }
}

// check if path is directory or file in the SSH remote device
int getRegisterTypeRemoteSSH(char *path){
    LIBSSH2_SFTP_ATTRIBUTES registerStat;
    err = libssh2_sftp_stat(sftp_session, path, &registerStat);
    if(err<0){
        printf("couldn't get the register stat from SSH remote device. error code: %d\n", err);
        return -1;
    }
    if(LIBSSH2_SFTP_S_ISDIR(registerStat.permissions)){
        return DIRECTORY_TYPE;
    }
    if(LIBSSH2_SFTP_S_ISREG(registerStat.permissions)){
        return FILE_TYPE;
    }
    printf("unknown type but probably it's a file!\n");
    return FILE_TYPE;
}

// check if path is directory or file in the SSH client device
int getRegisterTypeClientSSH(char *path){
    struct stat registerStat;
    if(stat(path, &registerStat)!=0){
        printf("couldn't get the register stat from SSH client device.\n");
        return -1;
    }
    if(S_ISDIR(registerStat.st_mode)){
        return DIRECTORY_TYPE;
    }
    if(S_ISREG(registerStat.st_mode)){
        return FILE_TYPE;
    }
    printf("unknown type but probably it's a file!\n");
    return FILE_TYPE;
}


void getDirectoryTreeRemoteSSH(char* sourcePath, sourcePath_t *sourcePath_head, int recursivity){
    if(sourcePath_head==NULL){
        printf("source path pointer empty!\n");
        return;
    }
    if(sourcePath==NULL || strcmp(sourcePath, "")==0){
        printf("source path empty!\n");
        return;
    }
    LIBSSH2_SFTP_HANDLE *sftp_dirHandle;
    sftp_dirHandle = libssh2_sftp_opendir(sftp_session, sourcePath);
    if(sftp_dirHandle==NULL){
        printf("couldn't open directory '%s' from SSH remote device. error code: %I32u.\n", sourcePath, libssh2_sftp_last_error(sftp_session));
        return;
    }
    int readBuffer;
    do {
        char registerName[1024*4];
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        readBuffer = libssh2_sftp_readdir(sftp_dirHandle, registerName, sizeof(registerName), &attrs);
        if(readBuffer > 0) {
            if(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
                if(strcmp(registerName, ".")!=0 && strcmp(registerName, "..")!=0){
                    printf("%s", registerName);
                    // set the new path (sub directory path)
                    char *newPath = (char*)calloc(strlen(sourcePath)+2+readBuffer, sizeof(char));
                    strcat(newPath, sourcePath);
                    strcat(newPath, "/");
                    strcat(newPath, registerName);
                    int registerType = 0;
                    if(LIBSSH2_SFTP_S_ISDIR(attrs.permissions)){
                        printf(" --dir-- \n");
                        registerType = DIRECTORY_TYPE;
                    }
                    else if(LIBSSH2_SFTP_S_ISREG(attrs.permissions)){
                        printf(" --file-- \n");
                        registerType = FILE_TYPE;
                    }
                    else{
                        printf("unknown register type is still a file type.\n");
                        registerType = FILE_TYPE;
                    }
                    // add the current path to the list source path before looping through the directory
                    addPathToListSourcePath(newPath, registerType);
                    // loop through the sub directory if recursivity option is enabled
                    if(registerType == DIRECTORY_TYPE && recursivity){
                        getDirectoryTreeRemoteSSH(newPath, sourcePath_head, recursivity);
                    }
                }
            }
            else {
                printf("couldn't get the register type.\n");
            }
        }
        else{
            break;
        }
    } while(1);
    libssh2_sftp_closedir(sftp_dirHandle);
}

void getDirectoryTreeClientSSH(char* sourcePath, sourcePath_t *sourcePath_head, int recursivity){
    if(sourcePath_head==NULL){
        printf("source path pointer empty!\n");
        return;
    }
    if(sourcePath==NULL || strcmp(sourcePath, "")==0){
        printf("source path empty!\n");
        return;
    }
    // open dir
    DIR *dir_handle = opendir(sourcePath);
    if(dir_handle==NULL){
        printf("couldn't open directory '%s' from SSH client device.\n", sourcePath);
        return;
    }
    
    char *subSourcePath=NULL;
    while(1) {
        struct dirent *dir_attrs;
        dir_attrs=readdir(dir_handle);
        if(dir_attrs==NULL){
            break;
        }
        if(strcmp(dir_attrs->d_name, ".")!=0 && strcmp(dir_attrs->d_name, "..")!=0){
            printf("found file/directory %s\n",dir_attrs->d_name);
            subSourcePath = (char*)calloc(strlen(sourcePath)+2+strlen(dir_attrs->d_name), sizeof(char));
            strcpy(subSourcePath, sourcePath);
            strcat(subSourcePath, "\\");
            strcat(subSourcePath, dir_attrs->d_name);
            int subSourcePath_type = getRegisterTypeClientSSH(subSourcePath);
            // add the current path to the list source path before looping through the directory
            addPathToListSourcePath(subSourcePath, subSourcePath_type);
            // loop through the sub directory if recursivity option is enabled
            if(subSourcePath_type == DIRECTORY_TYPE && recursivity){
                getDirectoryTreeClientSSH(subSourcePath, sourcePath_head, recursivity);
            }
            free(subSourcePath);
        }
    }
    closedir(dir_handle);
}

void parseOptions(int argc, char* argv[]){
    // set up options
    printf("set options, argc=%d %s\n", argc, argv[0]);
    int argPos=1;
    for(argPos=1; argPos<argc; argPos++){
        printf("%d %s \n", argPos, argv[argPos]);
        // ssh remote device ip
        if(strcmp(argv[argPos], "-ip")==0){
            argPos++;
            remote_ip = (char*)realloc(NULL, (strlen(argv[argPos])+1)*sizeof(char));
            strcpy(remote_ip, argv[argPos]);
        }
        // ssh port
        else if(strcmp(argv[argPos], "-port")==0){
            argPos++;
            remote_port = atoi(argv[argPos]);
        }
        // username
        else if(strcmp(argv[argPos], "-u")==0){
            argPos++;
            userName = (char*)realloc(NULL, (strlen(argv[argPos])+1)*sizeof(char));
            strcpy(userName, argv[argPos]);
        }
        // password
        else if(strcmp(argv[argPos], "-p")==0){
            argPos++;
            password = (char*)realloc(NULL, (strlen(argv[argPos])+1)*sizeof(char));
            strcpy(password, argv[argPos]);
        }
        // public key path
        else if(strcmp(argv[argPos], "-pubk")==0){
            argPos++;
            publicKeyPath = (char*)realloc(NULL, (strlen(argv[argPos])+1)*sizeof(char));
            strcpy(publicKeyPath, argv[argPos]);
            options &= ~OPTION_AUTH_MASK;
            options|=OPTION_AUTH_PUBKEY;
        }
        // private key path
        else if(strcmp(argv[argPos], "-prvk")==0){
            argPos++;
            privateKeyPath = (char*)realloc(NULL, (strlen(argv[argPos])+1)*sizeof(char));
            strcpy(privateKeyPath, argv[argPos]);
        }
        // download
        else if(strcmp(argv[argPos], "-download")==0){
            options &= ~OPTION_ACTION_MASK;
            options |= OPTION_DOWNLOAD;
        }
        // upload
        else if(strcmp(argv[argPos], "-upload")==0){
            options &= ~OPTION_ACTION_MASK;
            options |= OPTION_UPLOAD;
        }
        // source Path
        else if(strcmp(argv[argPos], "-s")==0){
            // add source path to list of source path without setting up the source path type (directory or file) because we don't know if the source path is from client or remote SSH
            argPos++;
            // check if the end of path is '/' or '\' and delete it because we don't need it
            if(argv[argPos][strlen(argv[argPos])-1]=='/' || argv[argPos][strlen(argv[argPos])-1]=='\\'){
                argv[argPos][strlen(argv[argPos])-1]='\0';
            }
            addPathToListSourcePath(argv[argPos], 0);
        }
        // recursive
        else if(strcmp(argv[argPos], "-r")==0){
            options &= ~OPTION_REC_MASK;
            options |= OPTION_REC;
        }
        // destination path
        else if(strcmp(argv[argPos], "-d")==0){
            argPos++;
            // check if the end of path is '/' or '\' and delete it because we don't need it
            if(argv[argPos][strlen(argv[argPos])-1]=='/' || argv[argPos][strlen(argv[argPos])-1]=='\\'){
                argv[argPos][strlen(argv[argPos])-1]='\0';
            }
            destinationPath = (char*)realloc(NULL, (strlen(argv[argPos])+1)*sizeof(char));
            strcpy(destinationPath, argv[argPos]);
        }
    }
    printf("options %d \n", options);
    printf("parseing option done\n");
}

int verifyLogingOptions(){
    // verify options (source path must be existe(exit if not found), destination path must be existe (exit if not found), recursivity should be used only on directory (worning if not the case))
    printf("verify options\n");
    int error = 0;
    printf("ip %s, ", remote_ip);
    if(remote_ip==NULL || strcmp(remote_ip, "")==0){
        printf("ssh remote ip not valid!");
        error = -1;
    }
    printf("port %d, ", remote_port);
    if(remote_port<0 || remote_port>65535){
        printf("ssh remote port not valid!");
        error = -1;
    }
    printf("userName %s, ", userName);
    if(userName==NULL || strcmp(userName, "")==0){
        printf("userName not valid!");
        error = -1;
    }
    printf("password %s, ", password);
    if(password==NULL){
        printf("password not valid!");
        error = -1;
    }
    if((options&OPTION_AUTH_MASK)==OPTION_AUTH_PUBKEY){
        if(publicKeyPath==NULL || strcmp(publicKeyPath,"")==0){
            printf("public key path is missing for public/private key authentication methid\n");
            error = -1;
        }
        if(privateKeyPath==NULL || strcmp(privateKeyPath,"")==0){
            printf("private key path is missing for public/private key authentication methid\n");
            error = -1;
        }
    }
    printf("verif login options done\n");
    return error;
}

int verifyTransferOptions(){
    int error = 0;
    printf("options %02X, ", options);
    // get and save the source path type (diretory or file)
    // if it's a download action, source path is in the SSH remote device
    // if it's an upload action, source path is in the SSH client device
    if((options&OPTION_ACTION_MASK)==OPTION_DOWNLOAD){
        printf("Download, ");
        listSourcePath->type = getRegisterTypeRemoteSSH(listSourcePath->path);
    }
    else if((options&OPTION_ACTION_MASK)==OPTION_UPLOAD){
        printf("Upload, ");
        printf("%s", listSourcePath->path);
        listSourcePath->type = getRegisterTypeClientSSH(listSourcePath->path);
    }
    else{
        printf("unknown option, Download or Upload?, ");
        error = -1;
    }
    printf("source path %s type %d, ", listSourcePath->path, listSourcePath->type);
    if(listSourcePath->path==NULL || strcmp(listSourcePath->path, "")==0){
        printf("source path not valid!");
        error = -1;
    }
    printf("recursivity %d, ", options&OPTION_REC_MASK);
    if(listSourcePath->type!=DIRECTORY_TYPE && (options&OPTION_REC_MASK)==OPTION_REC){
        printf("worning, no need to use recursivity for non directory source path!");
    }
    printf("destination %s\n", destinationPath);
    if(destinationPath==NULL || strcmp(destinationPath, "")==0){
        printf("destination path not valid!");
        error = -1;
    }
    printf("verif transfer options done\n");
    return error;
}

// create dir in SSH remote device.(this function will create the parent dir if not exist)
int createDirInRemoteSSH(char *dir){
    startCreateDirectoryAgain:
    err = libssh2_sftp_mkdir(sftp_session, dir, LIBSSH2_SFTP_S_IRWXG|LIBSSH2_SFTP_S_IRWXU|LIBSSH2_SFTP_S_IROTH);
    printf("create directory => %s\n", dir);
    if(err<0){
        // SFTP protocol error handler
        if(err==LIBSSH2_ERROR_EAGAIN){
            printf("LIBSSH2_ERROR_EAGAIN\n");
            // set this later.
            return -1; // for now it's an error
        }
        else if(err==LIBSSH2_ERROR_SFTP_PROTOCOL){
            printf("problem in creating directory: looking for a solution...\n");
            if(libssh2_sftp_last_error(sftp_session)==LIBSSH2_FX_FAILURE){
                printf("directory already existe.\n");
            }
            else if(libssh2_sftp_last_error(sftp_session)==LIBSSH2_FX_NO_SUCH_FILE){
                printf("maybe parent doesn't existe. try create parent.\n");
                int parentDirLen = strlen(dir)-strlen(strrchr(dir,'\\'));
                char *parentDir = (char*)calloc(parentDirLen+1, sizeof(char));
                strncpy(parentDir, dir, parentDirLen);
                if(createDirInRemoteSSH(parentDir)==0){
                    goto startCreateDirectoryAgain;
                }
                else{
                    printf("couldn't create parent directory!\n");
                    return -1;
                }
            }
            else{
                printf("couldn't create directory %s! error code: %d - %I32u\n",dir, err, libssh2_sftp_last_error(sftp_session));
                return -1;
            }
        }
        else{
            printf("couldn't create directory %s! error code: %d.\n",dir, err);
            return -1;
        }
    }
    else{
        printf("directory created => %s\n", dir);
    }
    return 0;
}

// create dir in SSH local device
int createDirInClientSSH(char *dir){
    startCreateDirectoryAgain:
#ifdef WIN32
    if(!CreateDirectory(dir, NULL)){
        if(GetLastError()!=ERROR_ALREADY_EXISTS){
#elif UNIX || LINUX
    err = mkdir(dir, 0774);
    if (err != 0) {
        if (err != EEXIST) {
#endif
            printf("problem in creating directory %s: looking for a solution...\n", dir);
            int parentDirLen = strlen(dir)-strlen(strrchr(dir,'\\'));
            char *parentDir = (char*)calloc(parentDirLen+1, sizeof(char));
            strncpy(parentDir, dir, parentDirLen);
            if(createDirInClientSSH(parentDir)==0){
                printf("back again to create dir %s\n", dir);
                goto startCreateDirectoryAgain;
            }
            else{
                printf("couldn't create parent directory %s\n", parentDir);
                return -1;
            }
        }
        else{
            printf("directory already in local device %s\n", dir);
            return 0;
        }
    }
    printf("directory created => %s\n", dir);
    return 0;
}

// upload file to the SSH remote server
int uploadFile(char *fileFullPath, char *destination){
    // open file source to make sure it's working, if it's not, exit the function without trying to create the file in the SSH remote side
    printf("file source => %s\n", fileFullPath);
    FILE *file_dp = fopen(fileFullPath, "rb");
    if(file_dp==NULL){
        printf("problem with file source %s!\n", fileFullPath);
        return -1;
    }

    LIBSSH2_SFTP_HANDLE *sftp_handle=NULL;
    // open/create file with those options (flags): write, if not exist create it, if exist truncated to 0 length (mean empty the file).
    sftp_handle = libssh2_sftp_open(sftp_session, destination, LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|LIBSSH2_FXF_TRUNC, LIBSSH2_SFTP_S_IRWXU|LIBSSH2_SFTP_S_IRWXG|LIBSSH2_SFTP_S_IROTH);
    if(sftp_handle==NULL){
        printf("couldn't open or create file %s! error code: %I32u\n",destination, libssh2_sftp_last_error(sftp_session));
        fclose(file_dp);
        return -1;
    }
    
    // get the source file size to read the whole file at once
    fseek(file_dp, 0, SEEK_END);
    size_t uploadBufferSize = ftell(file_dp);
    fseek(file_dp, 0, SEEK_SET);
    // file must be not empty to read and transfer its data.
    if(uploadBufferSize>0){
        size_t nbrDataRead = 0;
        char *uploadBuffer = (char*)malloc(uploadBufferSize*sizeof(char));
        continueUpload:
        // read from the file descriptor uploadBufferSize element (block), and each block of size one char which is one byte.
        nbrDataRead = fread(uploadBuffer,sizeof(char), uploadBufferSize, file_dp);
        // if read failed exit upload file
        if(nbrDataRead>0){
            // write data in file
            printf("upload the file to SSH remote by writing the data we read from SSH client file to SSH remote file\n");
            ssize_t nbrDataUploaded=0;
            nbrDataUploaded = libssh2_sftp_write(sftp_handle, uploadBuffer, nbrDataRead);
            if(nbrDataUploaded<0){
                printf("couldn't upload file %s to %s! error code: %d\n",fileFullPath, destination, err);
            }
            // if the total number of elements successfully read from source file was less then the source file size (uploadBufferSize), upload the rest of data
            // the condition of this to happen is very rare
            // not sure if the file pointer will stop at the last memory block the function read or the last memory block based on the uploadBuffer. verify this next time
            if(nbrDataRead < uploadBufferSize){
                printf("couldn't read all data from file. upload the rest\n");
                // new size
                uploadBufferSize -= nbrDataRead;
                uploadBuffer = (char*)realloc((char*)uploadBuffer, uploadBufferSize*sizeof(char));
                // back to read from file and upload the rest of data
                goto continueUpload;
            }
        }
        else{
            printf("reach end of source file or reading was failed!\n"); 
        }  
    }
    // close file and sftp handle
    fclose(file_dp);
    libssh2_sftp_close(sftp_handle);
    return 0;
}

// download file
int downloadFile(char *source, char *destination){
    
    // open file in read mode
    printf("file source => %s\n", source);
    LIBSSH2_SFTP_ATTRIBUTES sourceFileStat;
    err = libssh2_sftp_stat(sftp_session, source, &sourceFileStat);
    if(err<0){
        printf("something wrong with source file. error code: %d\n", err);
        return -1;
    }
    LIBSSH2_SFTP_HANDLE *sftp_handle=NULL;
    sftp_handle = libssh2_sftp_open(sftp_session, source, LIBSSH2_FXF_READ, 0);
    if(sftp_handle==NULL){
        printf("couldn't open source file %s! error code: %I32u\n",source, libssh2_sftp_last_error(sftp_session));
        return -1;
    }
    // open/create file in write and binary mode
    printf("file destination => %s\n", destination);
    FILE *file_dp = fopen(destination, "wb");
    if(file_dp==NULL){
        printf("couldn't create file %s!\n", destination);
        libssh2_sftp_close(sftp_handle);
        return -1;
    }
    size_t sourceFileSize = sourceFileStat.filesize;
    char *downloadBuffer;
    downloadBuffer = (char*) malloc(sourceFileSize*sizeof(char));
    ssize_t bufferSize;
    continueDownload:
    bufferSize = libssh2_sftp_read(sftp_handle, downloadBuffer, sourceFileSize);
    if(bufferSize<0){
        printf("couldn't read data from source file %s! error code: %I32u\n",source, libssh2_sftp_last_error(sftp_session));
        return -1;
    }
    else if(bufferSize>0){
        if(fwrite(downloadBuffer, sizeof(char), bufferSize, file_dp)!=bufferSize){
            printf("couldn't download all data from source file %s to destination file %s! error code: %d\n",source, destination, ferror(file_dp));
            return -1;
        }
        // check if we get all data from source file, if not, get the rest
        if(bufferSize<sourceFileSize){
            sourceFileSize -= bufferSize;
            downloadBuffer = (char*)realloc((char*)downloadBuffer, sourceFileSize*sizeof(char));
            // back to read from file and download the rest of data
            goto continueDownload;
        }
    }
    // close file and sftp handle
    printf("successfuly download source file %s to destination %s file.\n",source, destination);
    fclose(file_dp);
    libssh2_sftp_close(sftp_handle);
    return 0;   
}   

// upload section
void upload(){
    printf("start upload\n");
    // if the source path is a directory get all files and sub direcotries
    if(getRegisterTypeClientSSH(listSourcePath->path)==DIRECTORY_TYPE){
        getDirectoryTreeClientSSH(listSourcePath->path, listSourcePath, (options&OPTION_REC_MASK)==OPTION_REC);
    }
    // attempt to create the destination directory if not existe.
    if (createDirInRemoteSSH(destinationPath)!=0){
        // if the destination directory not existe and we couldn't create it, exit the program.
        printf("could create destination path\n");
        return;
    }
    sourcePath_t *sourcePath = listSourcePath;
    while(sourcePath!=NULL){
        // in the SSH remote server create the file/directory we will upload.
        // destination length is the sum of destinationPath length plus the absolut source directory length plus the difference between sourcepath and absolut source path 
        int destinationLen = strlen(destinationPath)+strlen(strrchr(listSourcePath->path,'\\'))+(strlen(sourcePath->path)-strlen(listSourcePath->path));
        char *destination =  (char*)calloc(destinationLen+1, sizeof(char));
        strcpy(destination, destinationPath);
        strcat(destination, strrchr(listSourcePath->path,'\\'));
        strrchr(destination,'\\')[0] = '/'; // change the last separation symbol
        unsigned int destination_pos = strlen(destination);
        unsigned int string_pos = strlen(listSourcePath->path);
        for(; string_pos<strlen(sourcePath->path); string_pos++){
            if(sourcePath->path[string_pos]=='\\'){
                destination[destination_pos]='/';
            }
            else{
                destination[destination_pos]=sourcePath->path[string_pos];
            }
            destination_pos++;

        }
        destination[destination_pos]='\0';
        printf("file destination in the SSH remote server => %s\n", destination);
        // because the way we create the listSourcePath which is order that parent directory come first so no missing path error should be exist
        if(sourcePath->type==DIRECTORY_TYPE){
            createDirInRemoteSSH(destination);
        }
        else if(sourcePath->type==FILE_TYPE){
            //printf("source path before upload %s\n", )
            uploadFile(sourcePath->path, destination);
        }
        sourcePath = sourcePath->nextSourcePath;
    }
}

// download section
void download(){
    printf("start download\n");
    // if the source path is a directory get all files and sub direcotries
    if(getRegisterTypeRemoteSSH(listSourcePath->path)==DIRECTORY_TYPE){
        getDirectoryTreeRemoteSSH(listSourcePath->path, listSourcePath, (options&OPTION_REC_MASK)==OPTION_REC);
    }
    // attempt to create the destination directory if not existe.
    if (createDirInClientSSH(destinationPath)!=0){
        // if the destination directory not existe and we couldn't create it, exit the program.
        printf("could create destination path\n");
        return;
    }
    sourcePath_t *sourcePath = listSourcePath;
    while(sourcePath!=NULL){
                // in the SSH remote server create the file/directory we will upload.
        // destination length is the sum of destinationPath length plus the absolut source directory length plus the difference between sourcepath and absolut source path 
        int destinationLen = strlen(destinationPath)+strlen(strrchr(listSourcePath->path,'/'))+(strlen(sourcePath->path)-strlen(listSourcePath->path));
        char *destination =  (char*)calloc(destinationLen+1, sizeof(char));
        strcpy(destination, destinationPath);
        strcat(destination, strrchr(listSourcePath->path,'/'));
        strrchr(destination,'/')[0] = '\\'; // change the last separation symbol
        unsigned int destination_pos = strlen(destination);
        unsigned int string_pos = strlen(listSourcePath->path);
        for(; string_pos<strlen(sourcePath->path); string_pos++){
            if(sourcePath->path[string_pos]=='/'){
                destination[destination_pos]='\\';
            }
            else{
                destination[destination_pos]=sourcePath->path[string_pos];
            }
            destination_pos++;

        }
        destination[destination_pos]='\0';
        printf("file destination in the SSH remote server => %s\n", destination);
        // because the way we create the listSourcePath which is order that parent directory come first so no missing path error should be exist
        if(sourcePath->type==DIRECTORY_TYPE){
            createDirInClientSSH(destination);
        }
        else if(sourcePath->type==FILE_TYPE){
            downloadFile(sourcePath->path, destination);
        }
        sourcePath = sourcePath->nextSourcePath;
    }
}


int main(int argc, char* argv[]){
    printf("Start program.\n");

    // get information from arguements and set options
    parseOptions(argc, argv);
    // verify login options
    if(verifyLogingOptions()!=0){
        return -1;
    }

#ifdef WIN32
    // init windows socket (winsock DLL)
    err = WSAStartup(MAKEWORD(2,0), &myWSAData);
    if(err < 0) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", err);
        return -1;
    }
#endif
    // Prepare socket for TCP/IP
    // AF_INET for IPv4; SOCK_STREAM for the type of the socket that supports the TCP protocol; 0 (or IPPROTO_TCP) for TCP protocol
    printf("Create socket.\n");
    mySocket = socket(AF_INET, SOCK_STREAM, 0);
#ifdef WIN32
    if(mySocket == INVALID_SOCKET){
        fprintf(stderr, "Failed to create socket! code error: %d\n", WSAGetLastError());
        return -1;
    }
#endif
    // connect to the remote server
    remote_sockaddr_in.sin_family = AF_INET;
    remote_sockaddr_in.sin_port = htons(remote_port);
    remote_sockaddr_in.sin_addr.s_addr = inet_addr(remote_ip);
    err = connect(mySocket, (struct sockaddr*)(&remote_sockaddr_in), sizeof(struct sockaddr_in));
    if(err != 0){
        fprintf(stderr, "Failed to connect to remote server! code error: %d\n", err);
        return -1;
    }

    // Init libssh2 functions
    // flag = 0 because we don't have any flag to consider (like LIBSSH2_INIT_NO_CRYPTO) in the initialization.
    printf("Initialze libssh2 library.\n");
    err = libssh2_init(0);
    if(err < 0){
        fprintf(stderr, "Can't init libssh2 functions! code error (%d).\n", err);
        return -1;
    }
    
    // Create session
    printf("Create SSH2 session.\n");
    mySession = libssh2_session_init();
    if(mySession == NULL){
        fprintf(stderr, "Failed to create SSH session! code error (%d).\n", err);
        goto exitProgram;
    }

    // trace: for debugging.
#ifdef LIBSSH2DEBUG
    libssh2_trace(mySession, LIBSSH2_TRACE_SOCKET|LIBSSH2_TRACE_TRANS|LIBSSH2_TRACE_KEX|LIBSSH2_TRACE_AUTH|LIBSSH2_TRACE_CONN|LIBSSH2_TRACE_SFTP|LIBSSH2_TRACE_ERROR|LIBSSH2_TRACE_PUBLICKEY);
#endif

    // Begin negotiation with remote server
    // This is a transport layer negotiation where client and remote server (host) exchange keys, setup the crypto, compression and MAC layers
    printf("Start the handshake with Remote server.\n");
    err = libssh2_session_handshake(mySession, mySocket);
    if(err != 0){
        fprintf(stderr, "Failed to negotiate with Remote server! code error (%d).\n", err);
        goto exitProgramFromSession;
    }

    // Get a list of the authentication methods are available by the host.
    printf("Get the list of authentication methods from the Remote server.\n");
    listAuth = libssh2_userauth_list(mySession, userName, strlen(userName));
    printf("    list: %s\n", listAuth);
    if(listAuth == NULL){
        fprintf(stderr, "No authentication method was detected.\n");
        goto exitProgramFromSession;
    }

    // Start authentication
    printf("Select authentication method.\n");
    if((strstr(listAuth,"publickey")!=NULL) && ((options&OPTION_AUTH_MASK)==OPTION_AUTH_PUBKEY)){
        // not available yet!
        printf("Start public key authentication method.\n");
        err = libssh2_userauth_publickey_fromfile(mySession, userName, publicKeyPath, privateKeyPath, password);
        if(err != 0){
            fprintf(stderr, "Authentication error. error code: %d\n", err);
            if(err==LIBSSH2_ERROR_AUTHENTICATION_FAILED){
                printf("    =>public key was not accepted\n");
            }
            else if(err==LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED){
                printf("    =>invalid username or public key\n");
            }
            else if(err==LIBSSH2_ERROR_EAGAIN){
                printf("    =>not a real failure.\n");
            }
            goto exitProgramFromSession;
        }
    }
    else if((strstr(listAuth,"password")!=NULL) && ((options&OPTION_AUTH_MASK)==OPTION_AUTH_PASSWORD)){
        printf("Start password authentication method.\n");
        err = libssh2_userauth_password(mySession, userName, password);
        if(err != 0){
            fprintf(stderr, "Authentication error. error code: %d\n", err);
            if(err==LIBSSH2_ERROR_AUTHENTICATION_FAILED){
                printf("    =>invalid username or password\n");
            }
            else if(err==LIBSSH2_ERROR_EAGAIN){
                printf("    =>not a real failure.\n");
            }
            goto exitProgramFromSession;
        }
    }
    else{
        fprintf(stderr, "Not supported authentication method.\n");
    }

   // Open/Establish SFTP session
    sftp_session = libssh2_sftp_init(mySession);
    if(sftp_session == NULL){
        printf("couldn't init SFTP session!\n");
        goto exitProgramFromSession;
    }

    /*
    * Meaning of blocking.
    * Set or clear blocking mode on the selected on the session. This will instantly affect any channels associated with this session.
    *  If a read is performed on a session with no data currently available:
    *   A blocking session will wait for data to arrive and return what it receives.
    *   A non-blocking session will return immediately with an empty buffer.
    *  If a write is performed on a session with no room for more data:
    *   A blocking session will wait for room.
    *   A non-blocking session will return immediately without writing anything.
    */

    // we wil use the blocking session mode to make sure to write the data to the SSH remote.
    libssh2_session_set_blocking(mySession, 1);

    // verify transfer options
    if(verifyTransferOptions()==0){
        // start upload/download
        if((options&OPTION_ACTION_MASK) == OPTION_UPLOAD){
            upload();
        }
        else if((options&OPTION_ACTION_MASK) == OPTION_DOWNLOAD){
            download();
        }
    }

    // shutdown
    sleep(1);
    libssh2_sftp_shutdown(sftp_session);
    exitProgramFromSession:
    libssh2_session_disconnect(mySession,"Shutdown system.");
    libssh2_session_free(mySession);
    exitProgram:
    printf("Exit program...\n");
    #ifdef WIN32
    closesocket(mySocket);
    #endif
    // close Libssh2 functions we initialized using the libssh2_init function
    libssh2_exit();
    return 0;
}
