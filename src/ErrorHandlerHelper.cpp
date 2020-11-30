#include "ErrorHandlerHelper.h"

#include <tchar.h>
#include <stdio.h>
#include <conio.h>

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