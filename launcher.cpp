// RE4 Coop - lanzador
//
// Ventana simple para elegir "Crear partida" (host) o "Unirme a una partida" (cliente), escribir la IP del
// host y abrir el juego. Escribe el re4coop.ini que lee el mod (dinput8.dll), asi no hay que editarlo a mano.
//
// Solo usa funciones de Windows (sin librerias externas). Todos los textos son ASCII a proposito.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <commdlg.h>
#include <shellapi.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

// ---------------------------------------------------------------- constantes

static const char* kWindowClass = "RE4CoopLauncher";
static const char* kSteamUri = "steam://rungameid/254700"; // Resident Evil 4 (2005) UHD en Steam
static const int kDefaultPort = 27015;

enum
{
	ID_RADIO_HOST = 101,
	ID_RADIO_JOIN,
	ID_LABEL_IP,
	ID_EDIT_IP,
	ID_LABEL_PORT,
	ID_EDIT_PORT,
	ID_CHECK_GHOST,
	ID_STATIC_RADMIN,
	ID_BTN_COPY,
	ID_STATIC_STATUS,
	ID_BTN_PLAY,
	ID_BTN_SAVE,
	ID_BTN_BROWSE,
	ID_BTN_DIRECT
};

// ---------------------------------------------------------------- estado

static HWND g_hwnd = nullptr;
static HWND g_radioHost = nullptr;
static HWND g_radioJoin = nullptr;
static HWND g_labelIp = nullptr;
static HWND g_editIp = nullptr;
static HWND g_labelPort = nullptr;
static HWND g_editPort = nullptr;
static HWND g_checkGhost = nullptr;
static HWND g_staticRadmin = nullptr;
static HWND g_btnCopy = nullptr;
static HWND g_staticStatus = nullptr;
static HWND g_btnPlay = nullptr;
static HWND g_btnSave = nullptr;
static HWND g_btnDirect = nullptr;

static char g_exeDir[MAX_PATH] = "";
static char g_gameDir[MAX_PATH] = ""; // carpeta donde esta bio4.exe (vacia si no se encontro)
static char g_radminIp[64] = "";

// ---------------------------------------------------------------- utilidades de archivos

static bool FileExists(const char* path)
{
	DWORD attr = GetFileAttributesA(path);
	return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static void JoinPath(const char* dir, const char* name, char* out, size_t outSize)
{
	snprintf(out, outSize, "%s\\%s", dir, name);
}

static void StripToDirectory(char* path)
{
	char* slash = strrchr(path, '\\');
	if (slash)
		*slash = 0;
}

static void GetLauncherIniPath(char* out, size_t outSize)
{
	JoinPath(g_exeDir, "re4coop_launcher.ini", out, outSize);
}

static void GetGameIniPath(char* out, size_t outSize)
{
	JoinPath(g_gameDir, "re4coop.ini", out, outSize);
}

static bool GameDirIsValid(const char* dir)
{
	if (!dir || !dir[0])
		return false;
	char exe[MAX_PATH];
	JoinPath(dir, "bio4.exe", exe, sizeof(exe));
	return FileExists(exe);
}

// Busca la carpeta del juego: primero al lado de este programa, despues la guardada la ultima vez.
static void ResolveGameDir()
{
	g_gameDir[0] = 0;
	if (GameDirIsValid(g_exeDir))
	{
		snprintf(g_gameDir, sizeof(g_gameDir), "%s", g_exeDir);
		return;
	}

	char iniPath[MAX_PATH];
	GetLauncherIniPath(iniPath, sizeof(iniPath));
	char saved[MAX_PATH] = "";
	GetPrivateProfileStringA("launcher", "juego", "", saved, sizeof(saved), iniPath);
	if (GameDirIsValid(saved))
		snprintf(g_gameDir, sizeof(g_gameDir), "%s", saved);
}

static void SaveGameDirChoice()
{
	char iniPath[MAX_PATH];
	GetLauncherIniPath(iniPath, sizeof(iniPath));
	WritePrivateProfileStringA("launcher", "juego", g_gameDir, iniPath);
}

// ---------------------------------------------------------------- IP de Radmin

// Radmin VPN usa direcciones 26.x.x.x. Busca una en las placas de red que estan activas.
static bool FindRadminIp(char* out, size_t outSize)
{
	ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
	ULONG size = 0;
	GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &size);
	if (size == 0)
		return false;

	std::vector<unsigned char> buffer(size);
	IP_ADAPTER_ADDRESSES* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
	if (GetAdaptersAddresses(AF_INET, flags, nullptr, adapters, &size) != NO_ERROR)
		return false;

	for (IP_ADAPTER_ADDRESSES* a = adapters; a != nullptr; a = a->Next)
	{
		if (a->OperStatus != IfOperStatusUp)
			continue;
		for (IP_ADAPTER_UNICAST_ADDRESS* u = a->FirstUnicastAddress; u != nullptr; u = u->Next)
		{
			if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET)
				continue;
			const sockaddr_in* sin = reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr);
			const unsigned char* b = reinterpret_cast<const unsigned char*>(&sin->sin_addr);
			if (b[0] == 26)
			{
				snprintf(out, outSize, "%u.%u.%u.%u", (unsigned)b[0], (unsigned)b[1], (unsigned)b[2], (unsigned)b[3]);
				return true;
			}
		}
	}
	return false;
}

// ---------------------------------------------------------------- validacion

static bool ParseIp(const char* text, char* normalized, size_t normSize)
{
	unsigned a = 0, b = 0, c = 0, d = 0;
	char extra = 0;
	int n = sscanf(text, " %u.%u.%u.%u %c", &a, &b, &c, &d, &extra);
	if (n != 4)
		return false;
	if (a > 255 || b > 255 || c > 255 || d > 255)
		return false;
	snprintf(normalized, normSize, "%u.%u.%u.%u", a, b, c, d);
	return true;
}

static bool ParsePort(const char* text, int* port)
{
	char* end = nullptr;
	long v = strtol(text, &end, 10);
	if (end == text)
		return false;
	while (*end == ' ')
		end++;
	if (*end != 0)
		return false;
	if (v < 1024 || v > 65535)
		return false;
	*port = (int)v;
	return true;
}

// ---------------------------------------------------------------- interfaz

static bool IsHostSelected()
{
	return SendMessageA(g_radioHost, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

static void GetEditText(HWND edit, char* out, size_t outSize)
{
	GetWindowTextA(edit, out, (int)outSize);
}

static void UpdateEnabledState()
{
	bool join = !IsHostSelected();
	EnableWindow(g_labelIp, join);
	EnableWindow(g_editIp, join);
	bool haveGame = g_gameDir[0] != 0;
	EnableWindow(g_btnPlay, haveGame);
	EnableWindow(g_btnSave, haveGame);
	EnableWindow(g_btnDirect, haveGame);
}

static void UpdateStatusText()
{
	char text[1024];
	if (g_gameDir[0] == 0)
	{
		snprintf(text, sizeof(text),
			"No encuentro bio4.exe.\r\n"
			"Copia este programa a la carpeta Bin32 del juego,\r\n"
			"o toca 'Buscar juego...' y elegi bio4.exe.");
	}
	else
	{
		char dll[MAX_PATH];
		JoinPath(g_gameDir, "dinput8.dll", dll, sizeof(dll));
		bool haveMod = FileExists(dll);
		snprintf(text, sizeof(text), "Juego: %s\r\nMod (dinput8.dll): %s", g_gameDir,
			haveMod ? "instalado" : "FALTA. Copia dinput8.dll a esa carpeta o el juego arrancara sin el mod.");
	}
	SetWindowTextA(g_staticStatus, text);
}

static void UpdateRadminText()
{
	char text[256];
	if (g_radminIp[0])
		snprintf(text, sizeof(text), "Tu IP de Radmin: %s\r\n(si creas la partida, pasale esta IP a tu amigo)", g_radminIp);
	else
		snprintf(text, sizeof(text), "No encuentro tu IP de Radmin.\r\nAbri Radmin VPN y conectate a la red de tu amigo.");
	SetWindowTextA(g_staticRadmin, text);
	EnableWindow(g_btnCopy, g_radminIp[0] != 0);
}

static void LoadSettingsIntoControls()
{
	// Valores por defecto (si todavia no existe el ini).
	bool host = true;
	char ip[64] = "";
	int port = kDefaultPort;
	bool ghost = true;

	if (g_gameDir[0])
	{
		char iniPath[MAX_PATH];
		GetGameIniPath(iniPath, sizeof(iniPath));
		if (FileExists(iniPath))
		{
			char mode[32] = "host";
			GetPrivateProfileStringA("coop", "modo", "host", mode, sizeof(mode), iniPath);
			host = _stricmp(mode, "client") != 0;
			GetPrivateProfileStringA("coop", "ip", "", ip, sizeof(ip), iniPath);
			port = (int)GetPrivateProfileIntA("coop", "puerto", kDefaultPort, iniPath);
			ghost = GetPrivateProfileIntA("fantasma", "activo", 1, iniPath) != 0;
		}
	}

	SendMessageA(g_radioHost, BM_SETCHECK, host ? BST_CHECKED : BST_UNCHECKED, 0);
	SendMessageA(g_radioJoin, BM_SETCHECK, host ? BST_UNCHECKED : BST_CHECKED, 0);
	SetWindowTextA(g_editIp, ip);
	char portText[16];
	snprintf(portText, sizeof(portText), "%d", port);
	SetWindowTextA(g_editPort, portText);
	SendMessageA(g_checkGhost, BM_SETCHECK, ghost ? BST_CHECKED : BST_UNCHECKED, 0);
}

// Valida lo que escribio la persona y escribe el re4coop.ini. Devuelve false (y avisa) si algo esta mal.
static bool SaveSettings()
{
	if (g_gameDir[0] == 0)
	{
		MessageBoxA(g_hwnd, "Primero hay que encontrar la carpeta del juego (boton 'Buscar juego...').", "RE4 Coop", MB_OK | MB_ICONWARNING);
		return false;
	}

	bool host = IsHostSelected();

	char ipText[64];
	GetEditText(g_editIp, ipText, sizeof(ipText));
	char ip[64] = "";
	if (!host)
	{
		if (!ParseIp(ipText, ip, sizeof(ip)))
		{
			MessageBoxA(g_hwnd,
				"La IP del host no es valida.\n\nTiene que ser como 26.123.45.67: es la IP de Radmin de tu amigo, "
				"que el ve en esta misma ventana cuando crea la partida.",
				"RE4 Coop", MB_OK | MB_ICONWARNING);
			SetFocus(g_editIp);
			return false;
		}
	}

	char portText[32];
	GetEditText(g_editPort, portText, sizeof(portText));
	int port = 0;
	if (!ParsePort(portText, &port))
	{
		MessageBoxA(g_hwnd, "El puerto no es valido. Usa un numero entre 1024 y 65535 (lo normal es 27015).", "RE4 Coop", MB_OK | MB_ICONWARNING);
		SetFocus(g_editPort);
		return false;
	}

	bool ghost = SendMessageA(g_checkGhost, BM_GETCHECK, 0, 0) == BST_CHECKED;

	char iniPath[MAX_PATH];
	GetGameIniPath(iniPath, sizeof(iniPath));

	char portOut[16];
	snprintf(portOut, sizeof(portOut), "%d", port);

	bool ok = true;
	ok = WritePrivateProfileStringA("coop", "modo", host ? "host" : "client", iniPath) && ok;
	if (!host)
		ok = WritePrivateProfileStringA("coop", "ip", ip, iniPath) && ok;
	ok = WritePrivateProfileStringA("coop", "puerto", portOut, iniPath) && ok;
	ok = WritePrivateProfileStringA("fantasma", "activo", ghost ? "1" : "0", iniPath) && ok;

	if (!ok)
	{
		char msg[600];
		snprintf(msg, sizeof(msg),
			"No pude escribir el archivo:\n%s\n\nProba abrir este programa como administrador, o mover el juego a una carpeta sin proteccion.", iniPath);
		MessageBoxA(g_hwnd, msg, "RE4 Coop", MB_OK | MB_ICONERROR);
		return false;
	}
	return true;
}

static void PlayThroughSteam()
{
	HINSTANCE r = ShellExecuteA(g_hwnd, "open", kSteamUri, nullptr, nullptr, SW_SHOWNORMAL);
	if ((INT_PTR)r <= 32)
	{
		MessageBoxA(g_hwnd,
			"No pude abrir el juego a traves de Steam.\n\nAbri Steam y proba de nuevo, o usa el boton 'Abrir bio4.exe directo'.",
			"RE4 Coop", MB_OK | MB_ICONWARNING);
	}
}

static void PlayDirect()
{
	char exe[MAX_PATH];
	JoinPath(g_gameDir, "bio4.exe", exe, sizeof(exe));
	HINSTANCE r = ShellExecuteA(g_hwnd, "open", exe, nullptr, g_gameDir, SW_SHOWNORMAL);
	if ((INT_PTR)r <= 32)
		MessageBoxA(g_hwnd, "No pude abrir bio4.exe.", "RE4 Coop", MB_OK | MB_ICONWARNING);
}

static void CopyRadminIp()
{
	if (!g_radminIp[0])
		return;
	if (!OpenClipboard(g_hwnd))
		return;
	EmptyClipboard();
	size_t len = strlen(g_radminIp) + 1;
	HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, len);
	if (mem)
	{
		void* p = GlobalLock(mem);
		if (p)
		{
			memcpy(p, g_radminIp, len);
			GlobalUnlock(mem);
			if (!SetClipboardData(CF_TEXT, mem))
				GlobalFree(mem);
		}
		else
		{
			GlobalFree(mem);
		}
	}
	CloseClipboard();
}

static void BrowseForGame()
{
	char file[MAX_PATH] = "";
	OPENFILENAMEA ofn;
	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = g_hwnd;
	ofn.lpstrFilter = "bio4.exe\0bio4.exe\0Todos los archivos\0*.*\0";
	ofn.lpstrFile = file;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrTitle = "Elegi bio4.exe (esta en la carpeta Bin32 del juego)";
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
	if (!GetOpenFileNameA(&ofn))
		return;

	StripToDirectory(file);
	if (!GameDirIsValid(file))
	{
		MessageBoxA(g_hwnd, "En esa carpeta no hay un bio4.exe.", "RE4 Coop", MB_OK | MB_ICONWARNING);
		return;
	}
	snprintf(g_gameDir, sizeof(g_gameDir), "%s", file);
	SaveGameDirChoice();
	LoadSettingsIntoControls();
	UpdateStatusText();
	UpdateEnabledState();
}

// ---------------------------------------------------------------- ventana

static HWND MakeControl(const char* cls, const char* text, DWORD style, DWORD exStyle, int x, int y, int w, int h, int id)
{
	HWND c = CreateWindowExA(exStyle, cls, text, WS_CHILD | WS_VISIBLE | style, x, y, w, h, g_hwnd,
		reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleA(nullptr), nullptr);
	if (c)
		SendMessageA(c, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
	return c;
}

static void CreateControls()
{
	g_radioHost = MakeControl("BUTTON", "Crear partida (yo soy el host)", BS_AUTORADIOBUTTON | WS_GROUP | WS_TABSTOP, 0, 16, 14, 400, 22, ID_RADIO_HOST);
	g_radioJoin = MakeControl("BUTTON", "Unirme a la partida de mi amigo", BS_AUTORADIOBUTTON, 0, 16, 40, 400, 22, ID_RADIO_JOIN);

	g_labelIp = MakeControl("STATIC", "IP de Radmin de tu amigo (el host):", SS_LEFT, 0, 16, 76, 200, 18, ID_LABEL_IP);
	g_editIp = MakeControl("EDIT", "", ES_AUTOHSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE, 220, 72, 200, 22, ID_EDIT_IP);
	g_labelPort = MakeControl("STATIC", "Puerto:", SS_LEFT, 0, 16, 106, 200, 18, ID_LABEL_PORT);
	g_editPort = MakeControl("EDIT", "", ES_AUTOHSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE, 220, 102, 80, 22, ID_EDIT_PORT);

	g_checkGhost = MakeControl("BUTTON", "Activar el fantasma automaticamente al empezar", BS_AUTOCHECKBOX | WS_TABSTOP, 0, 16, 136, 404, 22, ID_CHECK_GHOST);

	g_staticRadmin = MakeControl("STATIC", "", SS_LEFT, 0, 16, 168, 300, 36, ID_STATIC_RADMIN);
	g_btnCopy = MakeControl("BUTTON", "Copiar mi IP", BS_PUSHBUTTON | WS_TABSTOP, 0, 326, 166, 94, 24, ID_BTN_COPY);

	g_staticStatus = MakeControl("STATIC", "", SS_LEFT, 0, 16, 212, 404, 54, ID_STATIC_STATUS);

	g_btnPlay = MakeControl("BUTTON", "Guardar y jugar", BS_DEFPUSHBUTTON | WS_TABSTOP, 0, 16, 276, 150, 32, ID_BTN_PLAY);
	g_btnSave = MakeControl("BUTTON", "Solo guardar", BS_PUSHBUTTON | WS_TABSTOP, 0, 176, 276, 110, 32, ID_BTN_SAVE);
	MakeControl("BUTTON", "Buscar juego...", BS_PUSHBUTTON | WS_TABSTOP, 0, 296, 276, 124, 32, ID_BTN_BROWSE);
	g_btnDirect = MakeControl("BUTTON", "Abrir bio4.exe directo (sin Steam)", BS_PUSHBUTTON | WS_TABSTOP, 0, 16, 316, 404, 24, ID_BTN_DIRECT);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_COMMAND:
	{
		int id = LOWORD(wParam);
		switch (id)
		{
		case ID_RADIO_HOST:
		case ID_RADIO_JOIN:
			UpdateEnabledState();
			return 0;
		case ID_BTN_COPY:
			CopyRadminIp();
			return 0;
		case ID_BTN_BROWSE:
			BrowseForGame();
			return 0;
		case ID_BTN_SAVE:
			if (SaveSettings())
				MessageBoxA(g_hwnd, "Listo, guardado en re4coop.ini.", "RE4 Coop", MB_OK | MB_ICONINFORMATION);
			return 0;
		case ID_BTN_PLAY:
			if (SaveSettings())
				PlayThroughSteam();
			return 0;
		case ID_BTN_DIRECT:
			if (SaveSettings())
				PlayDirect();
			return 0;
		}
		break;
	}
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProcA(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nShow)
{
	GetModuleFileNameA(nullptr, g_exeDir, MAX_PATH);
	StripToDirectory(g_exeDir);

	WNDCLASSA wc;
	memset(&wc, 0, sizeof(wc));
	wc.lpfnWndProc = WndProc;
	wc.hInstance = hInstance;
	wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
	wc.hbrBackground = reinterpret_cast<HBRUSH>(static_cast<INT_PTR>(COLOR_BTNFACE + 1));
	wc.lpszClassName = kWindowClass;
	if (!RegisterClassA(&wc))
		return 1;

	RECT rc = { 0, 0, 436, 352 };
	DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
	AdjustWindowRect(&rc, style, FALSE);
	g_hwnd = CreateWindowExA(0, kWindowClass, "RE4 Coop - Lanzador", style, CW_USEDEFAULT, CW_USEDEFAULT,
		rc.right - rc.left, rc.bottom - rc.top, nullptr, nullptr, hInstance, nullptr);
	if (!g_hwnd)
		return 1;

	CreateControls();

	ResolveGameDir();
	if (!FindRadminIp(g_radminIp, sizeof(g_radminIp)))
		g_radminIp[0] = 0;
	LoadSettingsIntoControls();
	UpdateRadminText();
	UpdateStatusText();
	UpdateEnabledState();

	ShowWindow(g_hwnd, nShow);
	UpdateWindow(g_hwnd);

	MSG m;
	while (GetMessageA(&m, nullptr, 0, 0) > 0)
	{
		if (!IsDialogMessageA(g_hwnd, &m))
		{
			TranslateMessage(&m);
			DispatchMessageA(&m);
		}
	}
	return (int)m.wParam;
}
