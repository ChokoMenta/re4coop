// RE4 Coop - lanzador (v2, diseno nuevo)
//
// Ventana oscura y simple para crear una partida (host) o unirse a la de un amigo, y abrir el juego.
// Escribe el re4coop.ini que lee el mod (dinput8.dll), asi no hay que editarlo a mano.
// Encuentra el juego solo (busca en las bibliotecas de Steam), puede instalar/actualizar el mod con un boton,
// y tiene sala de espera: el juego se abre en las dos PCs cuando el amigo se une.
//
// Solo usa funciones de Windows (sin librerias externas). Los textos son ASCII a proposito.

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
#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------- constantes

static const char* kWindowClass = "RE4CoopLauncher2";
static const char* kSteamUri = "steam://rungameid/254700"; // Resident Evil 4 (2005) UHD en Steam
static const int kDefaultPort = 27015;

// Colores
static const COLORREF cBg = RGB(18, 20, 26);
static const COLORREF cHeader = RGB(26, 29, 38);
static const COLORREF cCard = RGB(30, 34, 44);
static const COLORREF cCardEdge = RGB(48, 53, 68);
static const COLORREF cInput = RGB(13, 15, 20);
static const COLORREF cText = RGB(232, 234, 240);
static const COLORREF cMuted = RGB(140, 147, 166);
static const COLORREF cAccent = RGB(208, 52, 44);
static const COLORREF cAccentDark = RGB(160, 38, 32);
static const COLORREF cOk = RGB(86, 200, 124);
static const COLORREF cWarn = RGB(238, 184, 60);
static const COLORREF cBad = RGB(232, 84, 84);

enum
{
	ID_MODE_HOST = 101,
	ID_MODE_JOIN,
	ID_EDIT_IP,
	ID_BTN_PASTE,
	ID_BTN_COPY,
	ID_EDIT_PORT,
	ID_TGL_GHOST,
	ID_TGL_WAIT,
	ID_BTN_PLAY,
	ID_BTN_SAVE,
	ID_BTN_BROWSE,
	ID_BTN_DIRECT,
	ID_BTN_CANCEL,
	ID_BTN_INSTALL
};

static const UINT_PTR kLobbyTimer = 1;
static const UINT_PTR kRefreshTimer = 2;

static const int kClientW = 460;
static const int kClientH = 608;

// ---------------------------------------------------------------- estado

static HWND g_hwnd = nullptr;
static HWND g_editIp = nullptr;
static HWND g_editPort = nullptr;
static HWND g_btnPaste = nullptr;
static HWND g_btnCopy = nullptr;
static HWND g_btnPlay = nullptr;
static HWND g_btnSave = nullptr;
static HWND g_btnBrowse = nullptr;
static HWND g_btnDirect = nullptr;
static HWND g_btnCancel = nullptr;
static HWND g_btnInstall = nullptr;
static HWND g_modeHost = nullptr;
static HWND g_modeJoin = nullptr;
static HWND g_tglGhost = nullptr;
static HWND g_tglWait = nullptr;

static HFONT g_fNormal = nullptr, g_fSmall = nullptr, g_fBig = nullptr, g_fTitle = nullptr, g_fBtn = nullptr;
static HBRUSH g_brInput = nullptr;

static bool g_hostMode = true;
static bool g_optGhost = true;
static bool g_optWait = true;

static char g_exeDir[MAX_PATH] = "";
static char g_gameDir[MAX_PATH] = ""; // carpeta donde esta bio4.exe (vacia si no se encontro)
static char g_radminIp[64] = "";

// Estado del mod en la carpeta del juego: 0 = falta, 1 = instalado, 2 = desactualizado
static int g_modState = 0;
static bool g_canInstall = false; // hay un dinput8.dll junto al lanzador que se puede copiar

// ---- sala de espera (lobby) ----
// El host espera a que el amigo se una y recien ahi se abre el juego en las dos PCs. Usa el puerto del mod + 1 (UDP).
enum LobbyState { LOBBY_IDLE = 0, LOBBY_HOST_WAIT, LOBBY_HOST_GO, LOBBY_CLIENT_WAIT };
static LobbyState g_lobby = LOBBY_IDLE;
static SOCKET g_lobbySock = INVALID_SOCKET;
static sockaddr_in g_lobbyPeer;
static bool g_lobbyPeerKnown = false;
static bool g_lobbyDirect = false;
static DWORD g_lobbyGoAt = 0;
static DWORD g_lobbyLastHello = 0;
static char g_banner[300] = "";
static const char* kMsgHello = "RE4C-LOBBY-HELLO";
static const char* kMsgWelcome = "RE4C-LOBBY-WELCOME";
static const char* kMsgGo = "RE4C-LOBBY-GO";

// ---------------------------------------------------------------- archivos

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

// Prueba una biblioteca de Steam: <biblioteca>\steamapps\common\Resident Evil 4\Bin32
static bool TryLibrary(const char* library, char* outDir, size_t outSize)
{
	char candidate[MAX_PATH];
	snprintf(candidate, sizeof(candidate), "%s\\steamapps\\common\\Resident Evil 4\\Bin32", library);
	if (GameDirIsValid(candidate))
	{
		snprintf(outDir, outSize, "%s", candidate);
		return true;
	}
	return false;
}

// Busca el juego en las bibliotecas de Steam (registro + libraryfolders.vdf).
static bool FindGameInSteam(char* outDir, size_t outSize)
{
	char steamPath[MAX_PATH] = "";
	HKEY key = nullptr;
	if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &key) == ERROR_SUCCESS)
	{
		DWORD size = sizeof(steamPath) - 1;
		DWORD type = 0;
		if (RegQueryValueExA(key, "SteamPath", nullptr, &type, reinterpret_cast<LPBYTE>(steamPath), &size) != ERROR_SUCCESS)
			steamPath[0] = 0;
		RegCloseKey(key);
	}
	if (!steamPath[0])
		return false;
	for (char* p = steamPath; *p; p++)
		if (*p == '/')
			*p = '\\';

	if (TryLibrary(steamPath, outDir, outSize))
		return true;

	// libraryfolders.vdf: lineas como   "path"		"E:\\Steam"
	char vdf[MAX_PATH];
	snprintf(vdf, sizeof(vdf), "%s\\steamapps\\libraryfolders.vdf", steamPath);
	FILE* f = fopen(vdf, "r");
	if (!f)
		return false;
	char line[1024];
	bool found = false;
	while (!found && fgets(line, sizeof(line), f))
	{
		char* tag = strstr(line, "\"path\"");
		if (!tag)
			continue;
		char* q1 = strchr(tag + 6, '"');
		if (!q1)
			continue;
		char* q2 = strchr(q1 + 1, '"');
		if (!q2)
			continue;
		char lib[MAX_PATH];
		size_t n = 0;
		for (char* c = q1 + 1; c < q2 && n + 1 < sizeof(lib); c++)
		{
			if (*c == '\\' && c + 1 < q2 && c[1] == '\\')
				c++; // "\\" -> "\"
			lib[n++] = (*c == '/') ? '\\' : *c;
		}
		lib[n] = 0;
		if (TryLibrary(lib, outDir, outSize))
			found = true;
	}
	fclose(f);
	return found;
}

// Busca la carpeta del juego: junto a este programa, la guardada la ultima vez, o en Steam.
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
	{
		snprintf(g_gameDir, sizeof(g_gameDir), "%s", saved);
		return;
	}

	char found[MAX_PATH];
	if (FindGameInSteam(found, sizeof(found)))
		snprintf(g_gameDir, sizeof(g_gameDir), "%s", found);
}

static void SaveGameDirChoice()
{
	char iniPath[MAX_PATH];
	GetLauncherIniPath(iniPath, sizeof(iniPath));
	WritePrivateProfileStringA("launcher", "juego", g_gameDir, iniPath);
}

// Mira si el mod esta en la carpeta del juego, y si hay uno distinto (mas nuevo) junto al lanzador.
static void RefreshModState()
{
	g_modState = 0;
	g_canInstall = false;
	if (!g_gameDir[0])
		return;

	char gameDll[MAX_PATH], localDll[MAX_PATH];
	JoinPath(g_gameDir, "dinput8.dll", gameDll, sizeof(gameDll));
	JoinPath(g_exeDir, "dinput8.dll", localDll, sizeof(localDll));

	bool haveGame = FileExists(gameDll);
	bool haveLocal = FileExists(localDll) && _stricmp(g_exeDir, g_gameDir) != 0;
	g_canInstall = haveLocal;
	g_modState = haveGame ? 1 : 0;

	if (haveGame && haveLocal)
	{
		WIN32_FILE_ATTRIBUTE_DATA a, b;
		if (GetFileAttributesExA(gameDll, GetFileExInfoStandard, &a) && GetFileAttributesExA(localDll, GetFileExInfoStandard, &b))
		{
			if (a.nFileSizeLow != b.nFileSizeLow || a.nFileSizeHigh != b.nFileSizeHigh)
				g_modState = 2;
		}
	}
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

static void GetEditText(HWND edit, char* out, size_t outSize)
{
	GetWindowTextA(edit, out, (int)outSize);
}

// ---------------------------------------------------------------- ajustes (re4coop.ini)

static void LoadSettings()
{
	g_hostMode = true;
	char ip[64] = "";
	int port = kDefaultPort;
	g_optGhost = true;

	if (g_gameDir[0])
	{
		char iniPath[MAX_PATH];
		GetGameIniPath(iniPath, sizeof(iniPath));
		if (FileExists(iniPath))
		{
			char mode[32] = "host";
			GetPrivateProfileStringA("coop", "modo", "host", mode, sizeof(mode), iniPath);
			g_hostMode = _stricmp(mode, "client") != 0 && _stricmp(mode, "cliente") != 0;
			GetPrivateProfileStringA("coop", "ip", "", ip, sizeof(ip), iniPath);
			port = (int)GetPrivateProfileIntA("coop", "puerto", kDefaultPort, iniPath);
			g_optGhost = GetPrivateProfileIntA("fantasma", "activo", 1, iniPath) != 0;
		}
	}

	char lini[MAX_PATH];
	GetLauncherIniPath(lini, sizeof(lini));
	g_optWait = GetPrivateProfileIntA("launcher", "esperar", 1, lini) != 0;

	SetWindowTextA(g_editIp, ip);
	char portText[16];
	snprintf(portText, sizeof(portText), "%d", port);
	SetWindowTextA(g_editPort, portText);
}

static void ShowMessage(const char* text, UINT icon)
{
	MessageBoxA(g_hwnd, text, "RE4 Coop", MB_OK | icon);
}

// Valida lo que escribio la persona y escribe el re4coop.ini. Devuelve false (y avisa) si algo esta mal.
static bool SaveSettings()
{
	if (g_gameDir[0] == 0)
	{
		ShowMessage("Primero hay que encontrar la carpeta del juego (boton 'Buscar juego...').", MB_ICONWARNING);
		return false;
	}

	char ipText[64];
	GetEditText(g_editIp, ipText, sizeof(ipText));
	char ip[64] = "";
	if (!g_hostMode)
	{
		if (!ParseIp(ipText, ip, sizeof(ip)))
		{
			ShowMessage("La IP del host no es valida.\n\nTiene que ser como 26.123.45.67: es la IP de Radmin de tu amigo, "
				"que el ve en esta misma ventana cuando crea la partida.", MB_ICONWARNING);
			SetFocus(g_editIp);
			return false;
		}
	}

	char portText[32];
	GetEditText(g_editPort, portText, sizeof(portText));
	int port = 0;
	if (!ParsePort(portText, &port))
	{
		ShowMessage("El puerto no es valido. Usa un numero entre 1024 y 65535 (lo normal es 27015).", MB_ICONWARNING);
		SetFocus(g_editPort);
		return false;
	}

	char iniPath[MAX_PATH];
	GetGameIniPath(iniPath, sizeof(iniPath));

	char portOut[16];
	snprintf(portOut, sizeof(portOut), "%d", port);

	bool ok = true;
	ok = WritePrivateProfileStringA("coop", "modo", g_hostMode ? "host" : "client", iniPath) && ok;
	if (!g_hostMode)
		ok = WritePrivateProfileStringA("coop", "ip", ip, iniPath) && ok;
	ok = WritePrivateProfileStringA("coop", "puerto", portOut, iniPath) && ok;
	ok = WritePrivateProfileStringA("fantasma", "activo", g_optGhost ? "1" : "0", iniPath) && ok;

	char lini[MAX_PATH];
	GetLauncherIniPath(lini, sizeof(lini));
	WritePrivateProfileStringA("launcher", "esperar", g_optWait ? "1" : "0", lini);

	if (!ok)
	{
		char msg[600];
		snprintf(msg, sizeof(msg),
			"No pude escribir el archivo:\n%s\n\nProba abrir este programa como administrador, o mover el juego a una carpeta sin proteccion.", iniPath);
		ShowMessage(msg, MB_ICONERROR);
		return false;
	}
	return true;
}

// ---------------------------------------------------------------- abrir el juego

static void PlayThroughSteam()
{
	HINSTANCE r = ShellExecuteA(g_hwnd, "open", kSteamUri, nullptr, nullptr, SW_SHOWNORMAL);
	if ((INT_PTR)r <= 32)
		ShowMessage("No pude abrir el juego a traves de Steam.\n\nAbri Steam y proba de nuevo, o usa el boton 'Sin Steam'.", MB_ICONWARNING);
}

static void PlayDirect()
{
	char exe[MAX_PATH];
	JoinPath(g_gameDir, "bio4.exe", exe, sizeof(exe));
	HINSTANCE r = ShellExecuteA(g_hwnd, "open", exe, nullptr, g_gameDir, SW_SHOWNORMAL);
	if ((INT_PTR)r <= 32)
		ShowMessage("No pude abrir bio4.exe.", MB_ICONWARNING);
}

static void LaunchGame(bool direct)
{
	if (direct)
		PlayDirect();
	else
		PlayThroughSteam();
}

static void CopyTextToClipboard(const char* text)
{
	if (!text[0] || !OpenClipboard(g_hwnd))
		return;
	EmptyClipboard();
	size_t len = strlen(text) + 1;
	HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, len);
	if (mem)
	{
		void* p = GlobalLock(mem);
		if (p)
		{
			memcpy(p, text, len);
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

static void PasteIntoIpEdit()
{
	if (!OpenClipboard(g_hwnd))
		return;
	HANDLE h = GetClipboardData(CF_TEXT);
	if (h)
	{
		const char* p = static_cast<const char*>(GlobalLock(h));
		if (p)
		{
			char buf[64];
			size_t n = 0;
			for (; p[n] && n + 1 < sizeof(buf); n++)
				buf[n] = p[n];
			buf[n] = 0;
			GlobalUnlock(h);
			// quitar espacios y saltos de linea de los costados
			while (n > 0 && (buf[n - 1] == ' ' || buf[n - 1] == '\r' || buf[n - 1] == '\n' || buf[n - 1] == '\t'))
				buf[--n] = 0;
			char* start = buf;
			while (*start == ' ' || *start == '\t')
				start++;
			SetWindowTextA(g_editIp, start);
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
		ShowMessage("En esa carpeta no hay un bio4.exe.", MB_ICONWARNING);
		return;
	}
	snprintf(g_gameDir, sizeof(g_gameDir), "%s", file);
	SaveGameDirChoice();
}

static void InstallMod()
{
	if (!g_gameDir[0] || !g_canInstall)
		return;
	char src[MAX_PATH], dst[MAX_PATH];
	JoinPath(g_exeDir, "dinput8.dll", src, sizeof(src));
	JoinPath(g_gameDir, "dinput8.dll", dst, sizeof(dst));
	if (!CopyFileA(src, dst, FALSE))
		ShowMessage("No pude copiar dinput8.dll a la carpeta del juego.\n\nCerra el juego si esta abierto, o proba abrir el lanzador como administrador.", MB_ICONERROR);
}

// ---------------------------------------------------------------- sala de espera

static void SetBanner(const char* text)
{
	snprintf(g_banner, sizeof(g_banner), "%s", text);
	InvalidateRect(g_hwnd, nullptr, FALSE);
}

static void UpdateControls()
{
	bool lobby = g_lobby != LOBBY_IDLE;
	bool haveGame = g_gameDir[0] != 0;

	// campos y botones segun el modo
	ShowWindow(g_editIp, (!g_hostMode && !lobby) ? SW_SHOW : SW_HIDE);
	ShowWindow(g_btnPaste, (!g_hostMode && !lobby) ? SW_SHOW : SW_HIDE);
	ShowWindow(g_btnCopy, (g_hostMode && !lobby) ? SW_SHOW : SW_HIDE);
	EnableWindow(g_btnCopy, g_radminIp[0] != 0);

	ShowWindow(g_btnPlay, lobby ? SW_HIDE : SW_SHOW);
	ShowWindow(g_btnCancel, lobby ? SW_SHOW : SW_HIDE);
	EnableWindow(g_btnPlay, haveGame);
	EnableWindow(g_btnSave, haveGame && !lobby);
	EnableWindow(g_btnDirect, haveGame && !lobby);
	EnableWindow(g_btnBrowse, !lobby);

	EnableWindow(g_modeHost, !lobby);
	EnableWindow(g_modeJoin, !lobby);
	EnableWindow(g_editPort, !lobby);
	EnableWindow(g_tglGhost, !lobby);
	EnableWindow(g_tglWait, !lobby);

	bool showInstall = !lobby && haveGame && g_canInstall && g_modState != 1;
	ShowWindow(g_btnInstall, showInstall ? SW_SHOW : SW_HIDE);

	InvalidateRect(g_hwnd, nullptr, FALSE);
}

static void LobbyClose()
{
	KillTimer(g_hwnd, kLobbyTimer);
	if (g_lobbySock != INVALID_SOCKET)
	{
		closesocket(g_lobbySock);
		g_lobbySock = INVALID_SOCKET;
	}
	g_lobby = LOBBY_IDLE;
	g_lobbyPeerKnown = false;
	g_banner[0] = 0;
	UpdateControls();
}

static void LobbySend(const char* msg)
{
	if (g_lobbySock == INVALID_SOCKET || !g_lobbyPeerKnown)
		return;
	sendto(g_lobbySock, msg, (int)strlen(msg), 0, reinterpret_cast<const sockaddr*>(&g_lobbyPeer), (int)sizeof(g_lobbyPeer));
}

// Empieza la sala de espera. Devuelve false (y avisa) si no se pudo abrir el puerto.
static bool LobbyStart(bool host, const char* hostIp, int gamePort, bool direct)
{
	LobbyClose();

	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
	{
		ShowMessage("No pude abrir la red para la sala de espera.", MB_ICONERROR);
		return false;
	}
	u_long nonBlocking = 1;
	ioctlsocket(s, FIONBIO, &nonBlocking);

	sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port = htons((unsigned short)(host ? gamePort + 1 : 0));
	if (bind(s, reinterpret_cast<sockaddr*>(&local), (int)sizeof(local)) == SOCKET_ERROR)
	{
		closesocket(s);
		char msg[300];
		snprintf(msg, sizeof(msg),
			"No pude usar el puerto %d (UDP) para la sala de espera.\n\nSi ya hay otro lanzador abierto, cerralo. "
			"Tambien podes cambiar el puerto (los dos tienen que poner el mismo).", gamePort + 1);
		ShowMessage(msg, MB_ICONWARNING);
		return false;
	}

	g_lobbySock = s;
	g_lobbyDirect = direct;
	g_lobbyPeerKnown = false;
	g_lobbyLastHello = 0;

	if (!host)
	{
		memset(&g_lobbyPeer, 0, sizeof(g_lobbyPeer));
		g_lobbyPeer.sin_family = AF_INET;
		g_lobbyPeer.sin_port = htons((unsigned short)(gamePort + 1));
		g_lobbyPeer.sin_addr.s_addr = inet_addr(hostIp);
		g_lobbyPeerKnown = true;
		g_lobby = LOBBY_CLIENT_WAIT;
		snprintf(g_banner, sizeof(g_banner), "Buscando a tu amigo (el host)...\nTiene que haber abierto el lanzador y tocado JUGAR.");
	}
	else
	{
		g_lobby = LOBBY_HOST_WAIT;
		if (g_radminIp[0])
			snprintf(g_banner, sizeof(g_banner), "Esperando a tu amigo...\nPasale tu IP: %s\nEl juego se abre solo cuando el se una.", g_radminIp);
		else
			snprintf(g_banner, sizeof(g_banner), "Esperando a tu amigo...\nEl juego se abre solo cuando el se una.");
	}

	UpdateControls();
	SetTimer(g_hwnd, kLobbyTimer, 200, nullptr);
	return true;
}

static void LobbyTick()
{
	if (g_lobby == LOBBY_IDLE || g_lobbySock == INVALID_SOCKET)
		return;

	DWORD now = GetTickCount();

	// Mensajes que llegaron.
	for (int guard = 0; guard < 32; guard++)
	{
		char buf[64];
		sockaddr_in from;
		int fromLen = (int)sizeof(from);
		int n = recvfrom(g_lobbySock, buf, (int)sizeof(buf) - 1, 0, reinterpret_cast<sockaddr*>(&from), &fromLen);
		if (n == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAECONNRESET)
				continue; // aviso de que un paquete anterior no llego: se ignora
			break;
		}
		buf[n] = 0;

		if (g_lobby == LOBBY_HOST_WAIT && strcmp(buf, kMsgHello) == 0)
		{
			g_lobbyPeer = from;
			g_lobbyPeerKnown = true;
			LobbySend(kMsgWelcome);
			g_lobby = LOBBY_HOST_GO;
			g_lobbyGoAt = now + 3000;
		}
		else if (g_lobby == LOBBY_HOST_GO && strcmp(buf, kMsgHello) == 0)
		{
			LobbySend(kMsgWelcome);
		}
		else if (g_lobby == LOBBY_CLIENT_WAIT && strcmp(buf, kMsgWelcome) == 0)
		{
			SetBanner("Conectado con el host.\nEsperando que abra el juego...");
		}
		else if (g_lobby == LOBBY_CLIENT_WAIT && strcmp(buf, kMsgGo) == 0)
		{
			bool direct = g_lobbyDirect;
			LobbyClose();
			LaunchGame(direct);
			return;
		}
	}

	if (g_lobby == LOBBY_CLIENT_WAIT)
	{
		if (now - g_lobbyLastHello >= 500)
		{
			g_lobbyLastHello = now;
			LobbySend(kMsgHello);
		}
	}
	else if (g_lobby == LOBBY_HOST_GO)
	{
		LobbySend(kMsgGo); // se repite para que no se pierda
		int left = (int)(g_lobbyGoAt - now);
		if (left <= 0)
		{
			for (int i = 0; i < 3; i++)
				LobbySend(kMsgGo);
			bool direct = g_lobbyDirect;
			LobbyClose();
			LaunchGame(direct);
			return;
		}
		char text[200];
		snprintf(text, sizeof(text), "Tu amigo se unio!\nAbriendo el juego en %d...", left / 1000 + 1);
		SetBanner(text);
	}
}

// Guarda la configuracion y abre el juego (con sala de espera si esta activada).
static void PlayRequested(bool direct)
{
	if (!SaveSettings())
		return;

	if (!g_optWait)
	{
		LaunchGame(direct);
		return;
	}

	char ipText[64], ip[64] = "";
	GetEditText(g_editIp, ipText, sizeof(ipText));
	ParseIp(ipText, ip, sizeof(ip));
	char portText[32];
	GetEditText(g_editPort, portText, sizeof(portText));
	int port = kDefaultPort;
	ParsePort(portText, &port);
	LobbyStart(g_hostMode, ip, port, direct);
}

// ---------------------------------------------------------------- dibujo

static HFONT MakeFont(int height, int weight)
{
	return CreateFontA(height, 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
		CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
}

static void FillRoundRect(HDC dc, const RECT& r, int radius, COLORREF fill, COLORREF edge)
{
	HBRUSH br = CreateSolidBrush(fill);
	HPEN pen = CreatePen(PS_SOLID, 1, edge);
	HGDIOBJ oldB = SelectObject(dc, br);
	HGDIOBJ oldP = SelectObject(dc, pen);
	RoundRect(dc, r.left, r.top, r.right, r.bottom, radius, radius);
	SelectObject(dc, oldB);
	SelectObject(dc, oldP);
	DeleteObject(br);
	DeleteObject(pen);
}

static void DrawTextAt(HDC dc, const char* text, int x, int y, int w, int h, HFONT font, COLORREF color, UINT flags)
{
	RECT r = { x, y, x + w, y + h };
	HGDIOBJ old = SelectObject(dc, font);
	SetTextColor(dc, color);
	SetBkMode(dc, TRANSPARENT);
	DrawTextA(dc, text, -1, &r, flags);
	SelectObject(dc, old);
}

static void DrawDot(HDC dc, int cx, int cy, COLORREF color)
{
	HBRUSH br = CreateSolidBrush(color);
	HPEN pen = CreatePen(PS_SOLID, 1, color);
	HGDIOBJ oldB = SelectObject(dc, br);
	HGDIOBJ oldP = SelectObject(dc, pen);
	Ellipse(dc, cx - 5, cy - 5, cx + 5, cy + 5);
	SelectObject(dc, oldB);
	SelectObject(dc, oldP);
	DeleteObject(br);
	DeleteObject(pen);
}

static void ShortenPath(const char* path, char* out, size_t outSize)
{
	size_t n = strlen(path);
	if (n <= 44)
	{
		snprintf(out, outSize, "%s", path);
		return;
	}
	snprintf(out, outSize, "...%s", path + n - 41);
}

static void PaintAll(HDC dc)
{
	// fondo
	RECT all = { 0, 0, kClientW, kClientH };
	HBRUSH bg = CreateSolidBrush(cBg);
	FillRect(dc, &all, bg);
	DeleteObject(bg);

	// cabecera
	RECT head = { 0, 0, kClientW, 78 };
	HBRUSH hb = CreateSolidBrush(cHeader);
	FillRect(dc, &head, hb);
	DeleteObject(hb);
	RECT line = { 0, 76, kClientW, 79 };
	HBRUSH ab = CreateSolidBrush(cAccent);
	FillRect(dc, &line, ab);
	DeleteObject(ab);
	DrawTextAt(dc, "RE4 COOP", 24, 10, 300, 40, g_fTitle, cText, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
	DrawTextAt(dc, "Resident Evil 4  -  multijugador por Radmin VPN", 26, 48, 410, 22, g_fSmall, cMuted, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

	bool lobby = g_lobby != LOBBY_IDLE;

	// tarjeta del modo
	RECT card = { 24, 158, kClientW - 24, 242 };
	FillRoundRect(dc, card, 14, cCard, cCardEdge);

	if (g_hostMode)
	{
		DrawTextAt(dc, "TU IP DE RADMIN", 44, 168, 250, 18, g_fSmall, cMuted, DT_LEFT | DT_SINGLELINE);
		if (g_radminIp[0])
		{
			DrawTextAt(dc, g_radminIp, 44, 188, 270, 34, g_fBig, cText, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
			DrawTextAt(dc, "Pasale esta IP a tu amigo", 44, 220, 270, 16, g_fSmall, cMuted, DT_LEFT | DT_SINGLELINE);
		}
		else
		{
			DrawTextAt(dc, "No detectada", 44, 188, 270, 34, g_fBig, cWarn, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
			DrawTextAt(dc, "Abri Radmin VPN y conectate a la red", 44, 220, 280, 16, g_fSmall, cMuted, DT_LEFT | DT_SINGLELINE);
		}
	}
	else
	{
		DrawTextAt(dc, "IP DEL HOST (LA DE RADMIN DE TU AMIGO)", 44, 168, 380, 18, g_fSmall, cMuted, DT_LEFT | DT_SINGLELINE);
		if (!lobby)
		{
			RECT box = { 40, 192, 318, 228 };
			FillRoundRect(dc, box, 8, cInput, cCardEdge);
		}
		else
		{
			char ipText[64];
			GetEditText(g_editIp, ipText, sizeof(ipText));
			DrawTextAt(dc, ipText, 44, 190, 330, 34, g_fBig, cText, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
		}
	}

	if (lobby)
	{
		// banner de la sala de espera
		RECT bn = { 24, 258, kClientW - 24, 392 };
		FillRoundRect(dc, bn, 14, cCard, cAccent);
		DrawTextAt(dc, "SALA DE ESPERA", 44, 270, 300, 18, g_fSmall, cAccent, DT_LEFT | DT_SINGLELINE);
		DrawTextAt(dc, g_banner, 44, 296, kClientW - 88, 84, g_fNormal, cText, DT_LEFT | DT_WORDBREAK);
	}
	else
	{
		// estado
		char text[160];
		COLORREF col;

		// juego
		if (g_gameDir[0])
		{
			char shortPath[96];
			ShortenPath(g_gameDir, shortPath, sizeof(shortPath));
			snprintf(text, sizeof(text), "Juego: %s", shortPath);
			col = cOk;
		}
		else
		{
			snprintf(text, sizeof(text), "No encuentro bio4.exe (toca 'Buscar juego...')");
			col = cBad;
		}
		DrawDot(dc, 34, 270, col);
		DrawTextAt(dc, text, 50, 260, kClientW - 80, 20, g_fNormal, cText, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

		// mod
		if (!g_gameDir[0])
		{
			snprintf(text, sizeof(text), "Mod: -");
			col = cMuted;
		}
		else if (g_modState == 1)
		{
			snprintf(text, sizeof(text), "Mod instalado");
			col = cOk;
		}
		else if (g_modState == 2)
		{
			snprintf(text, sizeof(text), "Mod desactualizado (hay uno nuevo junto al lanzador)");
			col = cWarn;
		}
		else
		{
			snprintf(text, sizeof(text), g_canInstall ? "Mod sin instalar (se puede instalar con un boton)" : "Falta dinput8.dll en la carpeta del juego");
			col = cBad;
		}
		DrawDot(dc, 34, 298, col);
		DrawTextAt(dc, text, 50, 288, kClientW - 190, 20, g_fNormal, cText, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

		// radmin
		if (g_radminIp[0])
		{
			snprintf(text, sizeof(text), "Radmin VPN conectado (%s)", g_radminIp);
			col = cOk;
		}
		else
		{
			snprintf(text, sizeof(text), "Radmin VPN no detectado");
			col = cWarn;
		}
		DrawDot(dc, 34, 326, col);
		DrawTextAt(dc, text, 50, 316, kClientW - 80, 20, g_fNormal, cText, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

		// opciones
		DrawTextAt(dc, "OPCIONES", 24, 348, 200, 16, g_fSmall, cMuted, DT_LEFT | DT_SINGLELINE);
		DrawTextAt(dc, "Puerto", 24, 412, 70, 30, g_fNormal, cText, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
		RECT pbox = { 92, 410, 176, 440 };
		FillRoundRect(dc, pbox, 8, cInput, cCardEdge);
	}

	// pie
	DrawTextAt(dc, "Dentro del juego: F7 abre el panel de conexion", 24, kClientH - 24, 410, 18, g_fSmall, cMuted, DT_LEFT | DT_SINGLELINE);
}

static bool IsToggleOn(int id)
{
	if (id == ID_TGL_GHOST)
		return g_optGhost;
	if (id == ID_TGL_WAIT)
		return g_optWait;
	return false;
}

static void DrawButton(const DRAWITEMSTRUCT* d)
{
	HDC dc = d->hDC;
	RECT r = d->rcItem;
	bool pressed = (d->itemState & ODS_SELECTED) != 0;
	bool disabled = (d->itemState & ODS_DISABLED) != 0;
	bool focus = (d->itemState & ODS_FOCUS) != 0;
	int id = (int)d->CtlID;

	// limpiar con el color de fondo de la ventana (las esquinas redondeadas)
	HBRUSH bg = CreateSolidBrush(cBg);
	FillRect(dc, &r, bg);
	DeleteObject(bg);

	char text[128];
	GetWindowTextA(d->hwndItem, text, sizeof(text));

	if (id == ID_TGL_GHOST || id == ID_TGL_WAIT)
	{
		bool on = IsToggleOn(id);
		int midY = (r.top + r.bottom) / 2;
		RECT track = { r.left, midY - 11, r.left + 44, midY + 11 };
		FillRoundRect(dc, track, 22, disabled ? cCardEdge : (on ? cAccent : cInput), on ? cAccentDark : cCardEdge);
		int knobX = on ? track.right - 20 : track.left + 2;
		RECT knob = { knobX, midY - 9, knobX + 18, midY + 9 };
		FillRoundRect(dc, knob, 18, cText, cText);
		DrawTextAt(dc, text, r.left + 58, r.top, r.right - r.left - 58, r.bottom - r.top, g_fNormal, disabled ? cMuted : cText,
			DT_LEFT | DT_SINGLELINE | DT_VCENTER);
		return;
	}

	COLORREF fill = cCard, edge = cCardEdge, textColor = cText;
	HFONT font = g_fBtn;
	int radius = 12;

	if (id == ID_MODE_HOST || id == ID_MODE_JOIN)
	{
		bool selected = (id == ID_MODE_HOST) ? g_hostMode : !g_hostMode;
		if (selected)
		{
			fill = cAccent;
			edge = cAccentDark;
		}
		else
		{
			fill = cCard;
			edge = cCardEdge;
			textColor = cMuted;
		}
	}
	else if (id == ID_BTN_PLAY)
	{
		fill = pressed ? cAccentDark : cAccent;
		edge = cAccentDark;
		radius = 16;
	}
	else if (id == ID_BTN_CANCEL)
	{
		fill = pressed ? cCardEdge : cCard;
		edge = cAccent;
	}
	else
	{
		fill = pressed ? cCardEdge : cCard;
		font = g_fNormal;
	}

	if (disabled)
	{
		fill = cCard;
		edge = cCardEdge;
		textColor = cMuted;
	}

	FillRoundRect(dc, r, radius, fill, edge);
	if (pressed && id != ID_BTN_PLAY)
		OffsetRect(&r, 0, 1);
	HGDIOBJ old = SelectObject(dc, font);
	SetTextColor(dc, textColor);
	SetBkMode(dc, TRANSPARENT);
	DrawTextA(dc, text, -1, &r, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
	SelectObject(dc, old);

	if (focus && !disabled)
	{
		RECT fr = d->rcItem;
		InflateRect(&fr, -4, -4);
		DrawFocusRect(dc, &fr);
	}
}

// ---------------------------------------------------------------- ventana

static HWND MakeButton(const char* text, int id, int x, int y, int w, int h)
{
	HWND c = CreateWindowExA(0, "BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, x, y, w, h, g_hwnd,
		reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleA(nullptr), nullptr);
	return c;
}

static HWND MakeEdit(int id, int x, int y, int w, int h)
{
	HWND c = CreateWindowExA(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, x, y, w, h, g_hwnd,
		reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleA(nullptr), nullptr);
	if (c)
		SendMessageA(c, WM_SETFONT, reinterpret_cast<WPARAM>(g_fBig), TRUE);
	return c;
}

static void CreateControls()
{
	g_modeHost = MakeButton("CREAR PARTIDA", ID_MODE_HOST, 24, 94, 204, 46);
	g_modeJoin = MakeButton("UNIRME", ID_MODE_JOIN, 232, 94, 204, 46);

	// IP del host (modo unirse): la caja se dibuja en PaintAll; el campo va adentro, sin borde
	g_editIp = MakeEdit(ID_EDIT_IP, 48, 198, 262, 26);
	g_btnPaste = MakeButton("Pegar", ID_BTN_PASTE, 334, 192, 86, 36);
	g_btnCopy = MakeButton("Copiar IP", ID_BTN_COPY, 322, 190, 98, 38);

	g_tglGhost = MakeButton("Mostrar al otro jugador (fantasma)", ID_TGL_GHOST, 24, 370, 412, 30);
	g_tglWait = MakeButton("Esperar a mi amigo antes de abrir el juego", ID_TGL_WAIT, 24, 450, 412, 30);

	// el puerto va en la caja dibujada
	g_editPort = MakeEdit(ID_EDIT_PORT, 100, 414, 70, 22);

	g_btnPlay = MakeButton("JUGAR", ID_BTN_PLAY, 24, 488, 412, 52);
	g_btnCancel = MakeButton("CANCELAR", ID_BTN_CANCEL, 24, 420, 412, 52);
	ShowWindow(g_btnCancel, SW_HIDE);

	g_btnInstall = MakeButton("Instalar mod", ID_BTN_INSTALL, 330, 284, 106, 28);
	ShowWindow(g_btnInstall, SW_HIDE);

	g_btnSave = MakeButton("Solo guardar", ID_BTN_SAVE, 24, 552, 132, 32);
	g_btnBrowse = MakeButton("Buscar juego...", ID_BTN_BROWSE, 164, 552, 132, 32);
	g_btnDirect = MakeButton("Sin Steam", ID_BTN_DIRECT, 304, 552, 132, 32);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_ERASEBKGND:
		return 1;
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hwnd, &ps);
		HDC mem = CreateCompatibleDC(hdc);
		HBITMAP bmp = CreateCompatibleBitmap(hdc, kClientW, kClientH);
		HGDIOBJ old = SelectObject(mem, bmp);
		PaintAll(mem);
		BitBlt(hdc, 0, 0, kClientW, kClientH, mem, 0, 0, SRCCOPY);
		SelectObject(mem, old);
		DeleteObject(bmp);
		DeleteDC(mem);
		EndPaint(hwnd, &ps);
		return 0;
	}
	case WM_DRAWITEM:
		DrawButton(reinterpret_cast<const DRAWITEMSTRUCT*>(lParam));
		return TRUE;
	case WM_CTLCOLOREDIT:
	{
		HDC dc = reinterpret_cast<HDC>(wParam);
		SetTextColor(dc, cText);
		SetBkColor(dc, cInput);
		return reinterpret_cast<LRESULT>(g_brInput);
	}
	case WM_COMMAND:
	{
		int id = LOWORD(wParam);
		switch (id)
		{
		case ID_MODE_HOST:
			g_hostMode = true;
			UpdateControls();
			return 0;
		case ID_MODE_JOIN:
			g_hostMode = false;
			UpdateControls();
			return 0;
		case ID_TGL_GHOST:
			g_optGhost = !g_optGhost;
			InvalidateRect(g_tglGhost, nullptr, FALSE);
			return 0;
		case ID_TGL_WAIT:
			g_optWait = !g_optWait;
			InvalidateRect(g_tglWait, nullptr, FALSE);
			return 0;
		case ID_BTN_COPY:
			CopyTextToClipboard(g_radminIp);
			return 0;
		case ID_BTN_PASTE:
			PasteIntoIpEdit();
			return 0;
		case ID_BTN_INSTALL:
			InstallMod();
			RefreshModState();
			UpdateControls();
			return 0;
		case ID_BTN_BROWSE:
			BrowseForGame();
			LoadSettings();
			RefreshModState();
			UpdateControls();
			return 0;
		case ID_BTN_SAVE:
			if (SaveSettings())
				ShowMessage("Listo, guardado en re4coop.ini.", MB_ICONINFORMATION);
			return 0;
		case ID_BTN_PLAY:
			PlayRequested(false);
			return 0;
		case ID_BTN_DIRECT:
			PlayRequested(true);
			return 0;
		case ID_BTN_CANCEL:
			LobbyClose();
			return 0;
		}
		break;
	}
	case WM_TIMER:
		if (wParam == kLobbyTimer)
		{
			LobbyTick();
		}
		else if (wParam == kRefreshTimer && g_lobby == LOBBY_IDLE)
		{
			// cada 2 segundos: por si se conecta Radmin o se copia el mod mientras el lanzador esta abierto
			char ip[64] = "";
			if (!FindRadminIp(ip, sizeof(ip)))
				ip[0] = 0;
			int oldMod = g_modState;
			bool oldCan = g_canInstall;
			RefreshModState();
			if (strcmp(ip, g_radminIp) != 0 || oldMod != g_modState || oldCan != g_canInstall)
			{
				snprintf(g_radminIp, sizeof(g_radminIp), "%s", ip);
				UpdateControls();
			}
		}
		return 0;
	case WM_DESTROY:
		LobbyClose();
		KillTimer(hwnd, kRefreshTimer);
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProcA(hwnd, msg, wParam, lParam);
}

typedef BOOL(WINAPI* SetProcessDPIAware_t)(void);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nShow)
{
	// Sin esto Windows agranda la ventana con zoom y se ve borrosa en pantallas de alta resolucion.
	HMODULE user32 = GetModuleHandleA("user32.dll");
	if (user32)
	{
		SetProcessDPIAware_t dpi = reinterpret_cast<SetProcessDPIAware_t>(GetProcAddress(user32, "SetProcessDPIAware"));
		if (dpi)
			dpi();
	}

	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
	GetModuleFileNameA(nullptr, g_exeDir, MAX_PATH);
	StripToDirectory(g_exeDir);

	g_fNormal = MakeFont(-16, FW_NORMAL);
	g_fSmall = MakeFont(-13, FW_NORMAL);
	g_fBig = MakeFont(-24, FW_SEMIBOLD);
	g_fTitle = MakeFont(-32, FW_BOLD);
	g_fBtn = MakeFont(-17, FW_BOLD);
	g_brInput = CreateSolidBrush(cInput);

	WNDCLASSA wc;
	memset(&wc, 0, sizeof(wc));
	wc.lpfnWndProc = WndProc;
	wc.hInstance = hInstance;
	wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
	wc.hbrBackground = nullptr;
	wc.lpszClassName = kWindowClass;
	if (!RegisterClassA(&wc))
		return 1;

	RECT rc = { 0, 0, kClientW, kClientH };
	DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;
	AdjustWindowRect(&rc, style, FALSE);
	g_hwnd = CreateWindowExA(0, kWindowClass, "RE4 Coop", style, CW_USEDEFAULT, CW_USEDEFAULT,
		rc.right - rc.left, rc.bottom - rc.top, nullptr, nullptr, hInstance, nullptr);
	if (!g_hwnd)
		return 1;

	CreateControls();

	ResolveGameDir();
	if (!FindRadminIp(g_radminIp, sizeof(g_radminIp)))
		g_radminIp[0] = 0;
	RefreshModState();
	LoadSettings();
	UpdateControls();
	SetTimer(g_hwnd, kRefreshTimer, 2000, nullptr);

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
