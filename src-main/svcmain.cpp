// svcmain.cpp - the entry point for service executables
// ___________
// \_   _____/ _____ ______   ___________  ___________ 
//  |    __)_ /     \\____ \_/ __ \_  __ \/  _ \_  __ \
//  |        \  Y Y  \  |_> >  ___/|  | \(  <_> )  | \/
// /_______  /__|_|  /   __/ \___  >__|   \____/|__|   
//         \/      \/|__|        \/                    
//

//                        ..::--:....                        
//                     .-#%%%%%%%%#*=:.......::-..           
//                  ..=#%%%%%@@@%%%%%%###***#***+=.          
//                 .-===##%%%%%%%#*+=--=+*--......           
//                .=+==+%%%%%%%%*-==*#%#:....                
//               .=-=+=#@@@@%%%%@@@%%%=.                     
//             .:==::==%%@%%%%%%%%%%%:.                      
//           .:+**=-::-=#%%%%%%%%%%*:.                       
//        ..-*****+=------=+##%%%#-...                       
//        .+****+++++==----===****=:..                       
//       .*#**+++++*+++++++++==-----=-..                     
//      .+#*+=+***####=-::--::::::::::..                     
//      :#*=+**####+:::::::::::::::::::..                    
//     .+*+***###+-:::::::::::::::...::..                    
//    .-*===*##*-:..::::::::::::....:::..                    
//    :#+=-=+#%*:...:::::::::..:::--:::..                    
//   .*+===++%*:::..::::::::...:::::::::..                   
//  .+*+++##*%-:::....::::::.......:::::..                   
//  :#+++*%#**:::.....:::::::::....::::-:.                   
// .+#*+*#%##-:::.....:::::::::::::::::-+.                   
// :*****#@#=:::.....::::::::::::::::::-#+                   
//.=*+***#%-:::.....:::::::::::::::::::-*%-                  
//.+*****#=-:::::...:::::::------:---:::-+%:                 

#include <windows.h>
#include "..\src-common\start.h"
#include "svcmain.h"


SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

void ServiceMain(int argc, char* argv[]);
void ControlHandler(DWORD request);

int main(int argc, char* argv[]) {
	SERVICE_TABLE_ENTRY ServiceTable[2] = { { NULL, NULL }, { NULL, NULL } };

	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
	ServiceTable[0].lpServiceName = (wchar_t *)SERVICE_NAME;

	StartServiceCtrlDispatcher(ServiceTable);
	return 0;
}

void ServiceMain(int argc, char* argv[]) {
	ServiceStatus.dwServiceType = SERVICE_WIN32;
	ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ServiceStatus.dwWin32ExitCode = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;

	hStatus = RegisterServiceCtrlHandler(SERVICE_NAME, (LPHANDLER_FUNCTION)ControlHandler);

	if (hStatus == (SERVICE_STATUS_HANDLE)NULL)
		return;

	start();
	ExitProcess(0);
}

void ControlHandler(DWORD request) {
	switch (request) {
	case SERVICE_CONTROL_STOP:
		ServiceStatus.dwWin32ExitCode = 0;
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(hStatus, &ServiceStatus);
		return;

	case SERVICE_CONTROL_SHUTDOWN:
		ServiceStatus.dwWin32ExitCode = 0;
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(hStatus, &ServiceStatus);
		return;

	default:
		break;
	}

	return;
}
