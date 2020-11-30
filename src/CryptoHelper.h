#pragma once

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

// usage example
//int _tmain( int argc, _TCHAR * argv[] )
//{
//    _tprintf(
//        TEXT( "ENCRYPT:\n" ) );
//    {
//        LPTSTR pszSource = "users.txt";
//        LPTSTR pszDestination = "users_encrypted.txt";
//        LPTSTR pszPassword = "superpass2000";
//
//        //---------------------------------------------------------------
//        // Call EncryptFile to do the actual encryption.
//        if( MyEncryptFile( pszSource, pszDestination, pszPassword ) )
//        {
//            _tprintf(
//                TEXT( "Encryption of the file %s was successful. \n" ),
//                pszSource );
//            _tprintf(
//                TEXT( "The encrypted data is in file %s.\n" ),
//                pszDestination );
//        }
//        else
//        {
//            MyHandleError(
//                TEXT( "Error encrypting file!\n" ),
//                GetLastError() );
//        }
//    }
//
//    _tprintf(
//        TEXT( "DECRYPT\n" ) );
//    {
//        LPTSTR pszSource = "users_encrypted.txt";
//        LPTSTR pszDestination = "users_decrypted.txt";
//        LPTSTR pszPassword = "superpass2000";
//
//        //---------------------------------------------------------------
//        // Call EncryptFile to do the actual encryption.
//        if( MyDecryptFile( pszSource, pszDestination, pszPassword ) )
//        {
//            _tprintf(
//                TEXT( "Encryption of the file %s was successful. \n" ),
//                pszSource );
//            _tprintf(
//                TEXT( "The encrypted data is in file %s.\n" ),
//                pszDestination );
//        }
//        else
//        {
//            MyHandleError(
//                TEXT( "Error encrypting file!\n" ),
//                GetLastError() );
//        }
//    }
//
//    return 0;
//}