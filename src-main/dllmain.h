/* rundll32.exe entry point ProcessDiagnostic */
void CALLBACK Processor(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow) {
	while (TRUE)
		WaitForSingleObject(GetCurrentProcess(), 60000);
}