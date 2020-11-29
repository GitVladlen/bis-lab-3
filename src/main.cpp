#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>

// Link with the Advapi32.lib file.
#pragma comment (lib, "advapi32")

#define ENCRYPT_PROV_TYPE PROV_RSA_AES
#define ENCRYPT_DATA_ALGORITHM CALG_AES_128
#define ENCRYPT_KEY_ALGORITHM CALG_MD2  
#define ENCRYPT_BLOCK_SIZE 8 

bool MyEncryptFile(
    LPTSTR szSource,
    LPTSTR szDestination,
    LPTSTR szPassword );

bool MyDecryptFile(
    LPTSTR szSource,
    LPTSTR szDestination,
    LPTSTR szPassword );

void MyHandleError(
    LPTSTR psz,
    int nErrorNumber );

int _tmain( int argc, _TCHAR * argv[] )
{
    _tprintf(
        TEXT( "ENCRYPT:\n" ) );
    {
        LPTSTR pszSource = "users.txt";
        LPTSTR pszDestination = "users_encrypted.txt";
        LPTSTR pszPassword = "superpass2000";

        if( argc >= 4 )
        {
            pszPassword = argv[3];
        }

        //---------------------------------------------------------------
        // Call EncryptFile to do the actual encryption.
        if( MyEncryptFile( pszSource, pszDestination, pszPassword ) )
        {
            _tprintf(
                TEXT( "Encryption of the file %s was successful. \n" ),
                pszSource );
            _tprintf(
                TEXT( "The encrypted data is in file %s.\n" ),
                pszDestination );
        }
        else
        {
            MyHandleError(
                TEXT( "Error encrypting file!\n" ),
                GetLastError() );
        }
    }

    _tprintf(
        TEXT( "DECRYPT\n" ) );
    {
        LPTSTR pszSource = "users_encrypted.txt";
        LPTSTR pszDestination = "users_decrypted.txt";
        LPTSTR pszPassword = "superpass2000";

        //---------------------------------------------------------------
        // Call EncryptFile to do the actual encryption.
        if( MyDecryptFile( pszSource, pszDestination, pszPassword ) )
        {
            _tprintf(
                TEXT( "Encryption of the file %s was successful. \n" ),
                pszSource );
            _tprintf(
                TEXT( "The encrypted data is in file %s.\n" ),
                pszDestination );
        }
        else
        {
            MyHandleError(
                TEXT( "Error encrypting file!\n" ),
                GetLastError() );
        }
    }

    return 0;
}

/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////

//-------------------------------------------------------------------
// Code for the function MyEncryptFile called by main.
//-------------------------------------------------------------------
// Parameters passed are:
//  pszSource, the name of the input, a plaintext file.
//  pszDestination, the name of the output, an encrypted file to be 
//   created.
//  pszPassword, either NULL if a password is not to be used or the 
//   string that is the password.
bool MyEncryptFile(
    LPTSTR pszSourceFile,
    LPTSTR pszDestinationFile,
    LPTSTR pszPassword )
{
    //---------------------------------------------------------------
    // Declare and initialize local variables.
    bool fReturn = false;
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE;

    HCRYPTPROV hCryptProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTKEY hXchgKey = NULL;
    HCRYPTHASH hHash = NULL;

    PBYTE pbKeyBlob = NULL;
    DWORD dwKeyBlobLen;

    PBYTE pbBuffer = NULL;
    DWORD dwBlockLen;
    DWORD dwBufferLen;
    DWORD dwCount;

    //---------------------------------------------------------------
    // Open the source file. 
    hSourceFile = CreateFile(
        pszSourceFile,
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL );
    if( INVALID_HANDLE_VALUE != hSourceFile )
    {
        _tprintf(
            TEXT( "The source plaintext file, %s, is open. \n" ),
            pszSourceFile );
    }
    else
    {
        MyHandleError(
            TEXT( "Error opening source plaintext file!\n" ),
            GetLastError() );
        goto Exit_MyEncryptFile;
    }

    //---------------------------------------------------------------
    // Open the destination file. 
    hDestinationFile = CreateFile(
        pszDestinationFile,
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL );
    if( INVALID_HANDLE_VALUE != hDestinationFile )
    {
        _tprintf(
            TEXT( "The destination file, %s, is open. \n" ),
            pszDestinationFile );
    }
    else
    {
        MyHandleError(
            TEXT( "Error opening destination file!\n" ),
            GetLastError() );
        goto Exit_MyEncryptFile;
    }

    //---------------------------------------------------------------
    // Get the handle to the default provider. 
    if( CryptAcquireContext(
        &hCryptProv,
        NULL,
        NULL,
        ENCRYPT_PROV_TYPE,
        0 ) )
    {
        _tprintf(
            TEXT( "A cryptographic provider has been acquired. \n" ) );
    }
    else
    {
        MyHandleError(
            TEXT( "Error during CryptAcquireContext!\n" ),
            GetLastError() );
        goto Exit_MyEncryptFile;
    }

    //---------------------------------------------------------------
    // Create the session key.
    //if( !pszPassword || !pszPassword[0] )
    //{
    //    //-----------------------------------------------------------
    //    // No password was passed.
    //    // Encrypt the file with a random session key, and write the 
    //    // key to a file. 

    //    //-----------------------------------------------------------
    //    // Create a random session key. 
    //    if( CryptGenKey(
    //        hCryptProv,
    //        ENCRYPT_DATA_ALGORITHM,
    //        KEYLENGTH | CRYPT_EXPORTABLE,
    //        &hKey ) )
    //    {
    //        _tprintf( TEXT( "A session key has been created. \n" ) );
    //    }
    //    else
    //    {
    //        MyHandleError(
    //            TEXT( "Error during CryptGenKey. \n" ),
    //            GetLastError() );
    //        goto Exit_MyEncryptFile;
    //    }

    //    //-----------------------------------------------------------
    //    // Get the handle to the exchange public key. 
    //    if( CryptGetUserKey(
    //        hCryptProv,
    //        AT_KEYEXCHANGE,
    //        &hXchgKey ) )
    //    {
    //        _tprintf(
    //            TEXT( "The user public key has been retrieved. \n" ) );
    //    }
    //    else
    //    {
    //        if( NTE_NO_KEY == GetLastError() )
    //        {
    //            // No exchange key exists. Try to create one.
    //            if( !CryptGenKey(
    //                hCryptProv,
    //                AT_KEYEXCHANGE,
    //                CRYPT_EXPORTABLE,
    //                &hXchgKey ) )
    //            {
    //                MyHandleError(
    //                    TEXT( "Could not create "
    //                        "a user public key.\n" ),
    //                    GetLastError() );
    //                goto Exit_MyEncryptFile;
    //            }
    //        }
    //        else
    //        {
    //            MyHandleError(
    //                TEXT( "User public key is not available and may " )
    //                TEXT( "not exist.\n" ),
    //                GetLastError() );
    //            goto Exit_MyEncryptFile;
    //        }
    //    }

    //    //-----------------------------------------------------------
    //    // Determine size of the key BLOB, and allocate memory. 
    //    if( CryptExportKey(
    //        hKey,
    //        hXchgKey,
    //        SIMPLEBLOB,
    //        0,
    //        NULL,
    //        &dwKeyBlobLen ) )
    //    {
    //        _tprintf(
    //            TEXT( "The key BLOB is %d bytes long. \n" ),
    //            dwKeyBlobLen );
    //    }
    //    else
    //    {
    //        MyHandleError(
    //            TEXT( "Error computing BLOB length! \n" ),
    //            GetLastError() );
    //        goto Exit_MyEncryptFile;
    //    }

    //    if( pbKeyBlob = (BYTE *)malloc( dwKeyBlobLen ) )
    //    {
    //        _tprintf(
    //            TEXT( "Memory is allocated for the key BLOB. \n" ) );
    //    }
    //    else
    //    {
    //        MyHandleError( TEXT( "Out of memory. \n" ), E_OUTOFMEMORY );
    //        goto Exit_MyEncryptFile;
    //    }

    //    //-----------------------------------------------------------
    //    // Encrypt and export the session key into a simple key 
    //    // BLOB. 
    //    if( CryptExportKey(
    //        hKey,
    //        hXchgKey,
    //        SIMPLEBLOB,
    //        0,
    //        pbKeyBlob,
    //        &dwKeyBlobLen ) )
    //    {
    //        _tprintf( TEXT( "The key has been exported. \n" ) );
    //    }
    //    else
    //    {
    //        MyHandleError(
    //            TEXT( "Error during CryptExportKey!\n" ),
    //            GetLastError() );
    //        goto Exit_MyEncryptFile;
    //    }

    //    //-----------------------------------------------------------
    //    // Release the key exchange key handle. 
    //    if( hXchgKey )
    //    {
    //        if( !(CryptDestroyKey( hXchgKey )) )
    //        {
    //            MyHandleError(
    //                TEXT( "Error during CryptDestroyKey.\n" ),
    //                GetLastError() );
    //            goto Exit_MyEncryptFile;
    //        }

    //        hXchgKey = 0;
    //    }

    //    //-----------------------------------------------------------
    //    // Write the size of the key BLOB to the destination file. 
    //    if( !WriteFile(
    //        hDestinationFile,
    //        &dwKeyBlobLen,
    //        sizeof( DWORD ),
    //        &dwCount,
    //        NULL ) )
    //    {
    //        MyHandleError(
    //            TEXT( "Error writing header.\n" ),
    //            GetLastError() );
    //        goto Exit_MyEncryptFile;
    //    }
    //    else
    //    {
    //        _tprintf( TEXT( "A file header has been written. \n" ) );
    //    }

    //    //-----------------------------------------------------------
    //    // Write the key BLOB to the destination file. 
    //    if( !WriteFile(
    //        hDestinationFile,
    //        pbKeyBlob,
    //        dwKeyBlobLen,
    //        &dwCount,
    //        NULL ) )
    //    {
    //        MyHandleError(
    //            TEXT( "Error writing header.\n" ),
    //            GetLastError() );
    //        goto Exit_MyEncryptFile;
    //    }
    //    else
    //    {
    //        _tprintf(
    //            TEXT( "The key BLOB has been written to the " )
    //            TEXT( "file. \n" ) );
    //    }

    //    // Free memory.
    //    free( pbKeyBlob );
    //}
    //else
    {

        //-----------------------------------------------------------
        // The file will be encrypted with a session key derived 
        // from a password.
        // The session key will be recreated when the file is 
        // decrypted only if the password used to create the key is 
        // available. 

        //-----------------------------------------------------------
        // Create a hash object. 
        if( CryptCreateHash(
            hCryptProv,
            ENCRYPT_KEY_ALGORITHM,
            0,
            0,
            &hHash ) )
        {
            _tprintf( TEXT( "A hash object has been created. \n" ) );
        }
        else
        {
            MyHandleError(
                TEXT( "Error during CryptCreateHash!\n" ),
                GetLastError() );
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // Hash the password. 
        if( CryptHashData(
            hHash,
            (BYTE *)pszPassword,
            lstrlen( pszPassword ),
            0 ) )
        {
            _tprintf(
                TEXT( "The password has been added to the hash. \n" ) );
        }
        else
        {
            MyHandleError(
                TEXT( "Error during CryptHashData. \n" ),
                GetLastError() );
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // Derive a session key from the hash object. 
        if( CryptDeriveKey(
            hCryptProv,
            ENCRYPT_DATA_ALGORITHM,
            hHash,
            CRYPT_EXPORTABLE | CRYPT_CREATE_SALT,
            &hKey ) )
        {
            _tprintf(
                TEXT( "An encryption key is derived from the " )
                TEXT( "password hash. \n" ) );
        }
        else
        {
            MyHandleError(
                TEXT( "Error during CryptDeriveKey!\n" ),
                GetLastError() );
            goto Exit_MyEncryptFile;
        }
    }

    //---------------------------------------------------------------
    // The session key is now ready. If it is not a key derived from 
    // a  password, the session key encrypted with the private key 
    // has been written to the destination file.

    //---------------------------------------------------------------
    // Determine the number of bytes to encrypt at a time. 
    // This must be a multiple of ENCRYPT_BLOCK_SIZE.
    // ENCRYPT_BLOCK_SIZE is set by a #define statement.
    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;

    //---------------------------------------------------------------
    // Determine the block size. If a block cipher is used, 
    // it must have room for an extra block. 
    if( ENCRYPT_BLOCK_SIZE > 1 )
    {
        dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
    }
    else
    {
        dwBufferLen = dwBlockLen;
    }

    //---------------------------------------------------------------
    // Allocate memory. 
    if( pbBuffer = (BYTE *)malloc( dwBufferLen ) )
    {
        _tprintf(
            TEXT( "Memory has been allocated for the buffer. \n" ) );
    }
    else
    {
        MyHandleError( TEXT( "Out of memory. \n" ), E_OUTOFMEMORY );
        goto Exit_MyEncryptFile;
    }

    //---------------------------------------------------------------
    // In a do loop, encrypt the source file, 
    // and write to the source file. 
    bool fEOF = FALSE;
    do
    {
        //-----------------------------------------------------------
        // Read up to dwBlockLen bytes from the source file. 
        if( !ReadFile(
            hSourceFile,
            pbBuffer,
            dwBlockLen,
            &dwCount,
            NULL ) )
        {
            MyHandleError(
                TEXT( "Error reading plaintext!\n" ),
                GetLastError() );
            goto Exit_MyEncryptFile;
        }

        if( dwCount < dwBlockLen )
        {
            fEOF = TRUE;
        }

        //-----------------------------------------------------------
        // Encrypt data. 
        if( !CryptEncrypt(
            hKey,
            NULL,
            fEOF,
            0,
            pbBuffer,
            &dwCount,
            dwBufferLen ) )
        {
            MyHandleError(
                TEXT( "Error during CryptEncrypt. \n" ),
                GetLastError() );
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // Write the encrypted data to the destination file. 
        if( !WriteFile(
            hDestinationFile,
            pbBuffer,
            dwCount,
            &dwCount,
            NULL ) )
        {
            MyHandleError(
                TEXT( "Error writing ciphertext.\n" ),
                GetLastError() );
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // End the do loop when the last block of the source file 
        // has been read, encrypted, and written to the destination 
        // file.
    } while( !fEOF );

    fReturn = true;

Exit_MyEncryptFile:
    //---------------------------------------------------------------
    // Close files.
    if( hSourceFile )
    {
        CloseHandle( hSourceFile );
    }

    if( hDestinationFile )
    {
        CloseHandle( hDestinationFile );
    }

    //---------------------------------------------------------------
    // Free memory. 
    if( pbBuffer )
    {
        free( pbBuffer );
    }


    //-----------------------------------------------------------
    // Release the hash object. 
    if( hHash )
    {
        if( !(CryptDestroyHash( hHash )) )
        {
            MyHandleError(
                TEXT( "Error during CryptDestroyHash.\n" ),
                GetLastError() );
        }

        hHash = NULL;
    }

    //---------------------------------------------------------------
    // Release the session key. 
    if( hKey )
    {
        if( !(CryptDestroyKey( hKey )) )
        {
            MyHandleError(
                TEXT( "Error during CryptDestroyKey!\n" ),
                GetLastError() );
        }
    }

    //---------------------------------------------------------------
    // Release the provider handle. 
    if( hCryptProv )
    {
        if( !(CryptReleaseContext( hCryptProv, 0 )) )
        {
            MyHandleError(
                TEXT( "Error during CryptReleaseContext!\n" ),
                GetLastError() );
        }
    }

    return fReturn;
} // End Encryptfile.

/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////

//-------------------------------------------------------------------
// Code for the function MyDecryptFile called by main.
//-------------------------------------------------------------------
// Parameters passed are:
//  pszSource, the name of the input file, an encrypted file.
//  pszDestination, the name of the output, a plaintext file to be 
//   created.
//  pszPassword, either NULL if a password is not to be used or the 
//   string that is the password.
bool MyDecryptFile(
    LPTSTR pszSourceFile,
    LPTSTR pszDestinationFile,
    LPTSTR pszPassword )
{
    //---------------------------------------------------------------
    // Declare and initialize local variables.
    bool fReturn = false;
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHash = NULL;

    HCRYPTPROV hCryptProv = NULL;

    DWORD dwCount;
    PBYTE pbBuffer = NULL;
    DWORD dwBlockLen;
    DWORD dwBufferLen;

    //---------------------------------------------------------------
    // Open the source file. 
    hSourceFile = CreateFile(
        pszSourceFile,
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL );
    if( INVALID_HANDLE_VALUE != hSourceFile )
    {
        _tprintf(
            TEXT( "The source encrypted file, %s, is open. \n" ),
            pszSourceFile );
    }
    else
    {
        MyHandleError(
            TEXT( "Error opening source plaintext file!\n" ),
            GetLastError() );
        goto Exit_MyDecryptFile;
    }

    //---------------------------------------------------------------
    // Open the destination file. 
    hDestinationFile = CreateFile(
        pszDestinationFile,
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL );
    if( INVALID_HANDLE_VALUE != hDestinationFile )
    {
        _tprintf(
            TEXT( "The destination file, %s, is open. \n" ),
            pszDestinationFile );
    }
    else
    {
        MyHandleError(
            TEXT( "Error opening destination file!\n" ),
            GetLastError() );
        goto Exit_MyDecryptFile;
    }

    //---------------------------------------------------------------
    // Get the handle to the default provider. 
    if( CryptAcquireContext(
        &hCryptProv,
        NULL,
        NULL,
        ENCRYPT_PROV_TYPE,
        0 ) )
    {
        _tprintf(
            TEXT( "A cryptographic provider has been acquired. \n" ) );
    }
    else
    {
        MyHandleError(
            TEXT( "Error during CryptAcquireContext!\n" ),
            GetLastError() );
        goto Exit_MyDecryptFile;
    }

    //---------------------------------------------------------------
    // Create the session key.
    //if( !pszPassword || !pszPassword[0] )
    //{
    //    //-----------------------------------------------------------
    //    // Decrypt the file with the saved session key. 

    //    DWORD dwKeyBlobLen;
    //    PBYTE pbKeyBlob = NULL;

    //    // Read the key BLOB length from the source file. 
    //    if( !ReadFile(
    //        hSourceFile,
    //        &dwKeyBlobLen,
    //        sizeof( DWORD ),
    //        &dwCount,
    //        NULL ) )
    //    {
    //        MyHandleError(
    //            TEXT( "Error reading key BLOB length!\n" ),
    //            GetLastError() );
    //        goto Exit_MyDecryptFile;
    //    }

    //    // Allocate a buffer for the key BLOB.
    //    if( !(pbKeyBlob = (PBYTE)malloc( dwKeyBlobLen )) )
    //    {
    //        MyHandleError(
    //            TEXT( "Memory allocation error.\n" ),
    //            E_OUTOFMEMORY );
    //    }

    //    //-----------------------------------------------------------
    //    // Read the key BLOB from the source file. 
    //    if( !ReadFile(
    //        hSourceFile,
    //        pbKeyBlob,
    //        dwKeyBlobLen,
    //        &dwCount,
    //        NULL ) )
    //    {
    //        MyHandleError(
    //            TEXT( "Error reading key BLOB length!\n" ),
    //            GetLastError() );
    //        goto Exit_MyDecryptFile;
    //    }

    //    //-----------------------------------------------------------
    //    // Import the key BLOB into the CSP. 
    //    if( !CryptImportKey(
    //        hCryptProv,
    //        pbKeyBlob,
    //        dwKeyBlobLen,
    //        0,
    //        0,
    //        &hKey ) )
    //    {
    //        MyHandleError(
    //            TEXT( "Error during CryptImportKey!/n" ),
    //            GetLastError() );
    //        goto Exit_MyDecryptFile;
    //    }

    //    if( pbKeyBlob )
    //    {
    //        free( pbKeyBlob );
    //    }
    //}
    //else
    {
        //-----------------------------------------------------------
        // Decrypt the file with a session key derived from a 
        // password. 

        //-----------------------------------------------------------
        // Create a hash object. 
        if( !CryptCreateHash(
            hCryptProv,
            ENCRYPT_KEY_ALGORITHM,
            0,
            0,
            &hHash ) )
        {
            MyHandleError(
                TEXT( "Error during CryptCreateHash!\n" ),
                GetLastError() );
            goto Exit_MyDecryptFile;
        }

        //-----------------------------------------------------------
        // Hash in the password data. 
        if( !CryptHashData(
            hHash,
            (BYTE *)pszPassword,
            lstrlen( pszPassword ),
            0 ) )
        {
            MyHandleError(
                TEXT( "Error during CryptHashData!\n" ),
                GetLastError() );
            goto Exit_MyDecryptFile;
        }

        //-----------------------------------------------------------
        // Derive a session key from the hash object. 
        if( !CryptDeriveKey(
            hCryptProv,
            ENCRYPT_DATA_ALGORITHM,
            hHash,
            CRYPT_EXPORTABLE | CRYPT_CREATE_SALT,
            &hKey ) )
        {
            MyHandleError(
                TEXT( "Error during CryptDeriveKey!\n" ),
                GetLastError() );
            goto Exit_MyDecryptFile;
        }
    }

    //---------------------------------------------------------------
    // The decryption key is now available, either having been 
    // imported from a BLOB read in from the source file or having 
    // been created by using the password. This point in the program 
    // is not reached if the decryption key is not available.

    //---------------------------------------------------------------
    // Determine the number of bytes to decrypt at a time. 
    // This must be a multiple of ENCRYPT_BLOCK_SIZE. 

    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
    dwBufferLen = dwBlockLen;

    //---------------------------------------------------------------
    // Allocate memory for the file read buffer. 
    if( !(pbBuffer = (PBYTE)malloc( dwBufferLen )) )
    {
        MyHandleError( TEXT( "Out of memory!\n" ), E_OUTOFMEMORY );
        goto Exit_MyDecryptFile;
    }

    //---------------------------------------------------------------
    // Decrypt the source file, and write to the destination file. 
    bool fEOF = false;
    do
    {
        //-----------------------------------------------------------
        // Read up to dwBlockLen bytes from the source file. 
        if( !ReadFile(
            hSourceFile,
            pbBuffer,
            dwBlockLen,
            &dwCount,
            NULL ) )
        {
            MyHandleError(
                TEXT( "Error reading from source file!\n" ),
                GetLastError() );
            goto Exit_MyDecryptFile;
        }

        if( dwCount <= dwBlockLen )
        {
            fEOF = TRUE;
        }

        //-----------------------------------------------------------
        // Decrypt the block of data. 
        if( !CryptDecrypt(
            hKey,
            0,
            fEOF,
            0,
            pbBuffer,
            &dwCount ) )
        {
            MyHandleError(
                TEXT( "Error during CryptDecrypt!\n" ),
                GetLastError() );
            goto Exit_MyDecryptFile;
        }

        //-----------------------------------------------------------
        // Write the decrypted data to the destination file. 
        if( !WriteFile(
            hDestinationFile,
            pbBuffer,
            dwCount,
            &dwCount,
            NULL ) )
        {
            MyHandleError(
                TEXT( "Error writing ciphertext.\n" ),
                GetLastError() );
            goto Exit_MyDecryptFile;
        }

        //-----------------------------------------------------------
        // End the do loop when the last block of the source file 
        // has been read, encrypted, and written to the destination 
        // file.
    } while( !fEOF );

    fReturn = true;

Exit_MyDecryptFile:

    //---------------------------------------------------------------
    // Free the file read buffer.
    if( pbBuffer )
    {
        free( pbBuffer );
    }

    //---------------------------------------------------------------
    // Close files.
    if( hSourceFile )
    {
        CloseHandle( hSourceFile );
    }

    if( hDestinationFile )
    {
        CloseHandle( hDestinationFile );
    }

    //-----------------------------------------------------------
    // Release the hash object. 
    if( hHash )
    {
        if( !(CryptDestroyHash( hHash )) )
        {
            MyHandleError(
                TEXT( "Error during CryptDestroyHash.\n" ),
                GetLastError() );
        }

        hHash = NULL;
    }

    //---------------------------------------------------------------
    // Release the session key. 
    if( hKey )
    {
        if( !(CryptDestroyKey( hKey )) )
        {
            MyHandleError(
                TEXT( "Error during CryptDestroyKey!\n" ),
                GetLastError() );
        }
    }

    //---------------------------------------------------------------
    // Release the provider handle. 
    if( hCryptProv )
    {
        if( !(CryptReleaseContext( hCryptProv, 0 )) )
        {
            MyHandleError(
                TEXT( "Error during CryptReleaseContext!\n" ),
                GetLastError() );
        }
    }

    return fReturn;
}


//-------------------------------------------------------------------
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to the  
//  standard error (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.

void MyHandleError( LPTSTR psz, int nErrorNumber )
{
    _ftprintf( stderr, TEXT( "An error occurred in the program. \n" ) );
    _ftprintf( stderr, TEXT( "%s\n" ), psz );
    _ftprintf( stderr, TEXT( "Error number %x.\n" ), nErrorNumber );
}

//#include <stdio.h>
//#include <windows.h>
//#include <Wincrypt.h>
//
//#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
//void MyHandleError( char * s );
//
//#define TOTAL_BYTES_READ    1024
//#define OFFSET_BYTES 1024
//
//#include "App.h"
//
//#include <sstream>
//
//BOOL ReadUserInfoFromRegistry( HKEY hKeyParent, LPSTR subkey, LPCSTR valueName, PBYTE * readData, DWORD * readDataLen )
//{
//    HKEY hKey;
//    DWORD len = TOTAL_BYTES_READ;
//    *readDataLen = len;
//    PBYTE readBuffer = (PBYTE)malloc( sizeof( PBYTE ) * len );
//    if( readBuffer == NULL )
//        return FALSE;
//    //Check if the registry exists
//    DWORD Ret = RegOpenKeyEx(
//        hKeyParent,
//        subkey,
//        0,
//        KEY_READ,
//        &hKey
//    );
//    if( Ret == ERROR_SUCCESS )
//    {
//        Ret = RegQueryValueEx(
//            hKey,
//            valueName,
//            NULL,
//            NULL,
//            (BYTE *)readBuffer,
//            readDataLen
//        );
//        while( Ret == ERROR_MORE_DATA )
//        {
//            // Get a buffer that is big enough.
//            len += OFFSET_BYTES;
//            readBuffer = (PBYTE)realloc( readBuffer, len );
//            *readDataLen = len;
//            Ret = RegQueryValueEx(
//                hKey,
//                valueName,
//                NULL,
//                NULL,
//                (BYTE *)readBuffer,
//                readDataLen
//            );
//        }
//        if( Ret != ERROR_SUCCESS )
//        {
//            RegCloseKey( hKey );
//            return false;;
//        }
//        *readData = readBuffer;
//        RegCloseKey( hKey );
//        return true;
//    }
//    else
//    {
//        return false;
//    }
//}
//
//
//std::string GetDataForHash()
//{
//    std::stringstream ss;
//
//    // number of mouse buttons
//    int mouseButtons = GetSystemMetrics( SM_CMOUSEBUTTONS );
//    ss << mouseButtons;
//
//    // screen height
//    int screenHeight = GetSystemMetrics( SM_CYSCREEN );
//    ss << screenHeight;
//
//    // list of disk devices
//    DWORD dwSize = MAX_PATH;
//    char szLogicalDrives[MAX_PATH] = { 0 };
//    DWORD dwResult = GetLogicalDriveStrings( dwSize, szLogicalDrives );
//
//    if( dwResult > 0 && dwResult <= MAX_PATH )
//    {
//        char * szSingleDrive = szLogicalDrives;
//        while( *szSingleDrive )
//        {
//            ss << szSingleDrive;
//
//            // get the next drive
//            szSingleDrive += strlen( szSingleDrive ) + 1;
//        }
//    }
//
//    // file system of current disk
//    char SysNameBuffer[MAX_PATH];
//
//    if( GetVolumeInformation(
//        NULL,
//        NULL,
//        0,
//        NULL,
//        NULL,
//        NULL,
//        SysNameBuffer,
//        sizeof( SysNameBuffer ) ) )
//    {
//        ss << SysNameBuffer;
//    }
//
//    return ss.str();
//}
//
//
//bool Check()
//{
//    //-------------------------------------------------------------------
//    // Get data for hash
//    std::string data = GetDataForHash();
//
//    printf( "Data for hash '%s'\n", data.c_str() );
//
//    //-------------------------------------------------------------------
//    // Declare and initialize variables.
//
//    LPSTR subKey = "Software\\Efremova";
//    LPCSTR valueName = "Signature";
//
//    PBYTE pbSignature = nullptr;
//    DWORD dwSigLen = 0;
//
//    //-------------------------------------------------------------------
//    // Read signature from registry
//
//    if( ReadUserInfoFromRegistry(
//        HKEY_CURRENT_USER,
//        subKey,
//        valueName,
//        &pbSignature,
//        &dwSigLen ) )
//    {
//        printf( "The signature has been read.\n" );
//    }
//    else
//    {
//        MyHandleError( "Error during ReadUserInfoFromRegistry." );
//        return false;
//    }
//
//    //-------------------------------------------------------------------
//    // Declare and initialize variables.
//
//    HCRYPTPROV hProv;
//    BYTE * pbBuffer = (BYTE *)data.c_str();
//    DWORD dwBufferLen = strlen( (char *)pbBuffer ) + 1;
//    HCRYPTHASH hHash;
//    HCRYPTKEY hKey;
//    HCRYPTKEY hPubKey;
//    BYTE * pbKeyBlob;
//    DWORD dwBlobLen;
//
//    //-------------------------------------------------------------------
//    // Acquire a cryptographic provider context handle.
//
//    if( CryptAcquireContext(
//        &hProv,
//        NULL,
//        NULL,
//        PROV_RSA_FULL,
//        0 ) )
//    {
//        printf( "CSP context acquired.\n" );
//    }
//    else
//    {
//        MyHandleError( "Error during CryptAcquireContext." );
//        if( pbSignature )
//            free( pbSignature );
//        return false;
//    }
//    //-------------------------------------------------------------------
//    // Get the public at signature key. This is the public key
//    // that will be used by the receiver of the hash to verify
//    // the signature. In situations where the receiver could obtain the
//    // sender's public key from a certificate, this step would not be
//    // needed.
//
//    if( CryptGetUserKey(
//        hProv,
//        AT_SIGNATURE,
//        &hKey ) )
//    {
//        printf( "The signature key has been acquired. \n" );
//    }
//    else
//    {
//        MyHandleError( "Error during CryptGetUserKey for signkey." );
//        if( pbSignature )
//            free( pbSignature );
//        if( hProv )
//            CryptReleaseContext( hProv, 0 );
//        return false;
//    }
//    ////-------------------------------------------------------------------
//    // Export the public key. Here the public key is exported to a 
//    // PUBLICKEYBOLB so that the receiver of the signed hash can
//    // verify the signature. This BLOB could be written to a file and
//    // sent to another user.
//
//    if( CryptExportKey(
//        hKey,
//        NULL,
//        PUBLICKEYBLOB,
//        0,
//        NULL,
//        &dwBlobLen ) )
//    {
//        printf( "Size of the BLOB for the public key determined. \n" );
//    }
//    else
//    {
//        MyHandleError( "Error computing BLOB length." );
//        if( pbSignature )
//            free( pbSignature );
//        if( hProv )
//            CryptReleaseContext( hProv, 0 );
//        return false;
//    }
//    //-------------------------------------------------------------------
//    // Allocate memory for the pbKeyBlob.
//
//    if( pbKeyBlob = (BYTE *)malloc( dwBlobLen ) )
//    {
//        printf( "Memory has been allocated for the BLOB. \n" );
//    }
//    else
//    {
//        MyHandleError( "Out of memory. \n" );
//        if( pbSignature )
//            free( pbSignature );
//        if( hProv )
//            CryptReleaseContext( hProv, 0 );
//        return false;
//    }
//    //-------------------------------------------------------------------
//    // Do the actual exporting into the key BLOB.
//
//    if( CryptExportKey(
//        hKey,
//        NULL,
//        PUBLICKEYBLOB,
//        0,
//        pbKeyBlob,
//        &dwBlobLen ) )
//    {
//        printf( "Contents have been written to the BLOB. \n" );
//    }
//    else
//    {
//        MyHandleError( "Error during CryptExportKey." );
//        if( pbSignature )
//            free( pbSignature );
//        if( hProv )
//            CryptReleaseContext( hProv, 0 );
//        return false;
//    }
//    //-------------------------------------------------------------------
//    // In the second phase, the hash signature is verified.
//    // This would most often be done by a different user in a
//    // separate program. The hash, signature, and the PUBLICKEYBLOB
//    // would be read from a file, an email message, 
//    // or some other source.
//
//    // Here, the original pbBuffer, pbSignature, szDescription. 
//    // pbKeyBlob, and their lengths are used.
//
//    // The contents of the pbBuffer must be the same data 
//    // that was originally signed.
//
//    //-------------------------------------------------------------------
//    // Get the public key of the user who created the digital signature 
//    // and import it into the CSP by using CryptImportKey. This returns
//    // a handle to the public key in hPubKey.
//
//    if( CryptImportKey(
//        hProv,
//        pbKeyBlob,
//        dwBlobLen,
//        0,
//        0,
//        &hPubKey ) )
//    {
//        printf( "The key has been imported.\n" );
//    }
//    else
//    {
//        MyHandleError( "Public key import failed." );
//        if( pbSignature )
//            free( pbSignature );
//        if( hProv )
//            CryptReleaseContext( hProv, 0 );
//        return false;
//    }
//    //-------------------------------------------------------------------
//    // Create a new hash object.
//
//    if( CryptCreateHash(
//        hProv,
//        CALG_MD5,
//        0,
//        0,
//        &hHash ) )
//    {
//        printf( "The hash object has been recreated. \n" );
//    }
//    else
//    {
//        MyHandleError( "Error during CryptCreateHash." );
//        if( pbSignature )
//            free( pbSignature );
//        if( hProv )
//            CryptReleaseContext( hProv, 0 );
//        return false;
//    }
//    //-------------------------------------------------------------------
//    // Compute the cryptographic hash of the buffer.
//
//    if( CryptHashData(
//        hHash,
//        pbBuffer,
//        dwBufferLen,
//        0 ) )
//    {
//        printf( "The new hash has been created.\n" );
//    }
//    else
//    {
//        MyHandleError( "Error during CryptHashData." );
//        if( pbSignature )
//            free( pbSignature );
//        if( hHash )
//            CryptDestroyHash( hHash );
//        if( hProv )
//            CryptReleaseContext( hProv, 0 );
//        return false;
//    }
//    //-------------------------------------------------------------------
//    // Validate the digital signature.
//
//    if( CryptVerifySignature(
//        hHash,
//        pbSignature,
//        dwSigLen,
//        hPubKey,
//        NULL,
//        0 ) )
//    {
//        printf( "The signature has been verified.\n" );
//    }
//    else
//    {
//        printf( "Signature not validated!\n" );
//        if( pbSignature )
//            free( pbSignature );
//        if( hHash )
//            CryptDestroyHash( hHash );
//        if( hProv )
//            CryptReleaseContext( hProv, 0 );
//        return false;
//    }
//    //-------------------------------------------------------------------
//    // Free memory to be used to store signature.
//
//    if( pbSignature )
//        free( pbSignature );
//
//    //-------------------------------------------------------------------
//    // Destroy the hash object.
//
//    if( hHash )
//        CryptDestroyHash( hHash );
//
//    //-------------------------------------------------------------------
//    // Release the provider handle.
//
//    if( hProv )
//        CryptReleaseContext( hProv, 0 );
//
//    return true;
//}
//
//void main()
//{
//    if( Check() == false )
//    {
//        printf( "Check signature from registry failed!\n" );
//        return;
//    }
//	App app = App();
//	app.run();
//}
//
//void MyHandleError( char * s )
//{
//    fprintf( stderr, "An error occurred in running the program. \n" );
//    fprintf( stderr, "%s\n", s );
//    fprintf( stderr, "Error number %x.\n", GetLastError() );
//} // End of MyHandleError