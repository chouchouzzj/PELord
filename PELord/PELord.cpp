// PELord.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
//#include "ParsePE.h"
#include "PeParser.h"

FILE *pFResult;

void TcharToChar(const TCHAR * tchar, char * _char)
{
	int iLength;
	//获取字节长度   
	iLength = WideCharToMultiByte(CP_ACP, 0, tchar, -1, NULL, 0, NULL, NULL);
	//将tchar值赋给_char    
	WideCharToMultiByte(CP_ACP, 0, tchar, -1, _char, iLength, NULL, NULL);
}

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc < 2){
		printf("\nUsage:\n"\
			"PELord.exe target.exe\n"\
			"PELord.exe target.dll\n"\
			"logfile is result.txt!\n"\
			);
		return 0;
	}
	_TCHAR _LogFile[MAX_PATH] = { 0 };
	char LogFile[MAX_PATH] = { 0 };
	lstrcpy(_LogFile, argv[1]);
	lstrcat(_LogFile, L".log");
	TcharToChar(_LogFile, LogFile);
	fopen_s(&pFResult, LogFile, "w");

	//CParsePE parsePE(L"D:\\notepad.exe");
	//parsePE.ParseDosHeader();
	//parsePE.ParseNtHeader();
	//parsePE.ParseImportTable();
	//parsePE.ParseDelayImportTable();
	//parsePE.ParseBoundImportTable();
	//parsePE.ParseDebugTable();
	//parsePE.ParseResouceTable();

	CPeParser parsePE(argv[1]);
	if (parsePE.is_pe_file() == true){
		parsePE.ParseDosHeader();
		parsePE.ParseNtHeader();
		parsePE.ParseExportTable();		
		parsePE.ParseImportTable();
		parsePE.ParseDelayImportTable();
		parsePE.ParseBoundImportTable();
		parsePE.ParseDebugTable();
		parsePE.ParseResouceTable();
	}

	fclose(pFResult);
	return 0;
}
