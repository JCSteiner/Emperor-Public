#include "..\EmperorXLL\stdafx.h"
#include "..\src-common\start.h"

// This is the function we are using to actually start the execution.
short __stdcall xlAutoOpen()
{
	DWORD error = start();

	return 0;
}