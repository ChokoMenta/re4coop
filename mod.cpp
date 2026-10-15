// RE4 Coop - hito 2: conexion entre dos PCs.
//
// Que hace:
//  1. Igual que el hito 1: encuentra a Leon en la memoria del juego.
//  2. Lee la configuracion de re4coop.ini (junto a bio4.exe): modo host o client, IP y puerto.
//  3. Abre una conexion UDP entre las dos PCs y se manda 20 veces por segundo la posicion de Leon.
//  4. Cada segundo escribe en re4coop.log la posicion propia y la del amigo.
//
// Todavia no aparece nada en pantalla: la prueba es que el log de cada PC muestre
// la posicion del otro jugador cambiando.

// winsock2.h tiene que ir ANTES de windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

// ---------------------------------------------------------------- archivos junto al .exe

// Arma la ruta completa de un archivo que vive en la misma carpeta que bio4.exe.
static bool ExeDirFile(const char* fileName, char* out, size_t outSize)
{
	char path[MAX_PATH];
	DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
	if (n == 0 || n >= MAX_PATH)
		return false;

	char* slash = strrchr(path, '\\');
	if (!slash)
		return false;
	slash[1] = '\0';

	if (strlen(path) + strlen(fileName) + 1 > outSize)
		return false;

	strcpy(out, path);
	strcat(out, fileName);
	return true;
}

// ---------------------------------------------------------------- log

static FILE* g_log = nullptr;

static void LogOpen()
{
	char path[MAX_PATH];
	if (!ExeDirFile("re4coop.log", path, MAX_PATH))
		return;

	g_log = fopen(path, "w");
}

static void Log(const char* fmt, ...)
{
	if (!g_log)
		return;

	va_list args;
	va_start(args, fmt);
	fprintf(g_log, "[%8lu] ", (unsigned long)GetTickCount());
	vfprintf(g_log, fmt, args);
	fprintf(g_log, "\n");
	va_end(args);
	fflush(g_log);
}

// ---------------------------------------------------------------- buscador de patrones

struct Pattern
{
	std::vector<uint8_t> bytes;
	std::vector<uint8_t> mask; // 1 = hay que comparar, 0 = comodin (?)
};

static bool ParsePattern(const char* text, Pattern& out)
{
	out.bytes.clear();
	out.mask.clear();

	const char* p = text;
	while (*p)
	{
		while (*p == ' ')
			p++;
		if (!*p)
			break;

		if (*p == '?')
		{
			out.bytes.push_back(0);
			out.mask.push_back(0);
			while (*p == '?')
				p++;
		}
		else
		{
			char* end = nullptr;
			unsigned long v = strtoul(p, &end, 16);
			if (end == p || v > 0xFF)
				return false;
			out.bytes.push_back((uint8_t)v);
			out.mask.push_back(1);
			p = end;
		}
	}
	return !out.bytes.empty();
}

// Busca el patron en las secciones ejecutables del .exe. Devuelve cuantas coincidencias hubo
// y deja en "first" la direccion de la primera.
static int ScanExe(const Pattern& pat, uintptr_t& first)
{
	first = 0;
	int count = 0;

	uint8_t* base = (uint8_t*)GetModuleHandleA(nullptr);
	auto dos = (PIMAGE_DOS_HEADER)base;
	auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
	auto sec = IMAGE_FIRST_SECTION(nt);

	const size_t plen = pat.bytes.size();

	for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
	{
		if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
			continue;

		uint8_t* start = base + sec->VirtualAddress;
		size_t size = sec->Misc.VirtualSize;
		if (size < plen)
			continue;

		for (size_t off = 0; off + plen <= size; off++)
		{
			bool ok = true;
			for (size_t k = 0; k < plen; k++)
			{
				if (pat.mask[k] && start[off + k] != pat.bytes[k])
				{
					ok = false;
					break;
				}
			}
			if (ok)
			{
				if (count == 0)
					first = (uintptr_t)(start + off);
				count++;
			}
		}
	}
	return count;
}

// Busca un patron y devuelve la direccion donde esta guardado el puntero (el operando
// de 4 bytes que aparece "offset" bytes despues del inicio del patron).
static uintptr_t FindGlobalPointer(const char* name, const char* patternText, int offset)
{
	Pattern pat;
	if (!ParsePattern(patternText, pat))
	{
		Log("ERROR: patron invalido para %s", name);
		return 0;
	}

	uintptr_t addr = 0;
	int count = ScanExe(pat, addr);
	if (count == 0)
	{
		Log("ERROR: no se encontro el patron de %s (el juego puede ser otra version)", name);
		return 0;
	}
	if (count > 1)
		Log("AVISO: el patron de %s coincide %d veces, uso la primera", name, count);

	uintptr_t operandAddr = addr + offset;
	uintptr_t globalAddr = *(uintptr_t*)operandAddr;
	Log("OK: %s -> instruccion en 0x%08X, variable global en 0x%08X", name, (unsigned)addr, (unsigned)globalAddr);
	return globalAddr;
}

// ---------------------------------------------------------------- lectura del jugador

struct PlayerInfo
{
	uintptr_t obj;
	float pos[3];   // cCoord::pos_94 (la posicion real)
	float angY;     // cCoord::ang_A0.y (hacia donde mira)
};

// Lee a Leon o a Ashley de forma segura: si algo falla no se cuelga el juego.
// (Funcion sin objetos C++ a proposito: asi se puede usar __try.)
static bool ReadPlayer(uintptr_t globalPtrAddr, PlayerInfo* out)
{
	__try
	{
		uintptr_t obj = *(uintptr_t*)globalPtrAddr;
		if (!obj)
			return false;

		// Mismo chequeo que usa re4_tweaks: el primer dato del objeto (tabla virtual)
		// tiene que ser una direccion razonable.
		if (*(uint32_t*)obj < 0x10000)
			return false;

		out->obj = obj;
		memcpy(out->pos, (void*)(obj + 0x94), sizeof(out->pos));
		memcpy(&out->angY, (void*)(obj + 0xA0 + 4), sizeof(out->angY));
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
}

// ---------------------------------------------------------------- configuracion (re4coop.ini)

struct Config
{
	bool isHost;
	char ip[64];
	int port;
};

static void WriteDefaultConfig(const char* path)
{
	FILE* f = fopen(path, "w");
	if (!f)
		return;

	fputs(
		"; Configuracion de RE4 Coop\r\n"
		"; modo: host = el que espera la conexion. client = el que se conecta al host.\r\n"
		"; ip: SOLO para el client. Es la IP de Radmin VPN del host (empieza con 26.)\r\n"
		"; puerto: tiene que ser el mismo en las dos PCs.\r\n"
		"[coop]\r\n"
		"modo=host\r\n"
		"ip=\r\n"
		"puerto=27015\r\n",
		f);
	fclose(f);
}

static bool LoadConfig(Config& cfg)
{
	memset(&cfg, 0, sizeof(cfg));

	char path[MAX_PATH];
	if (!ExeDirFile("re4coop.ini", path, MAX_PATH))
		return false;

	if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES)
	{
		WriteDefaultConfig(path);
		Log("No existia re4coop.ini: se creo uno nuevo con modo=host");
	}

	char mode[32];
	GetPrivateProfileStringA("coop", "modo", "host", mode, sizeof(mode), path);
	GetPrivateProfileStringA("coop", "ip", "", cfg.ip, sizeof(cfg.ip), path);
	cfg.port = (int)GetPrivateProfileIntA("coop", "puerto", 27015, path);

	if (lstrcmpiA(mode, "host") == 0)
		cfg.isHost = true;
	else if (lstrcmpiA(mode, "client") == 0 || lstrcmpiA(mode, "cliente") == 0)
		cfg.isHost = false;
	else
	{
		Log("ERROR: en re4coop.ini, modo='%s' no es valido (usar host o client)", mode);
		return false;
	}

	if (cfg.port < 1024 || cfg.port > 65535)
	{
		Log("ERROR: en re4coop.ini, puerto=%d no es valido (usar entre 1024 y 65535)", cfg.port);
		return false;
	}

	if (!cfg.isHost && cfg.ip[0] == '\0')
	{
		Log("ERROR: en re4coop.ini falta la ip (modo=client necesita la IP de Radmin del host)");
		return false;
	}

	Log("Configuracion: modo=%s ip='%s' puerto=%d", cfg.isHost ? "host" : "client", cfg.ip, cfg.port);
	return true;
}

// ---------------------------------------------------------------- red (UDP)

#pragma pack(push, 1)
struct NetPacket
{
	uint32_t magic;   // numero fijo para reconocer nuestros paquetes
	uint16_t version;
	uint16_t flags;   // bit 0: Leon esta en juego (no en menu/carga)
	uint32_t seq;     // numero de paquete
	float pos[3];
	float yaw;
};
#pragma pack(pop)
static_assert(sizeof(NetPacket) == 28, "tamano inesperado del paquete");

static const uint32_t NET_MAGIC = 0x43344552u;
static const uint16_t NET_VERSION = 1;
static const uint16_t FLAG_IN_GAME = 1;

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

static SOCKET g_sock = INVALID_SOCKET;
static sockaddr_in g_peer;
static bool g_peerKnown = false;
static bool g_isHost = false;

struct RemoteState
{
	bool everReceived;
	bool connected;
	DWORD lastRecvTick;
	uint16_t flags;
	float pos[3];
	float yaw;
	int packetsThisSecond;
};
static RemoteState g_remote;

static void AddrToString(const sockaddr_in& a, char* out, size_t outSize)
{
	char ip[64] = "?";
	inet_ntop(AF_INET, (void*)&a.sin_addr, ip, sizeof(ip));
	snprintf(out, outSize, "%s:%d", ip, (int)ntohs(a.sin_port));
}

static bool SameAddr(const sockaddr_in& a, const sockaddr_in& b)
{
	return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

static bool NetInit(const Config& cfg)
{
	g_isHost = cfg.isHost;
	memset(&g_remote, 0, sizeof(g_remote));

	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		Log("ERROR: no se pudo iniciar Winsock");
		return false;
	}

	g_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (g_sock == INVALID_SOCKET)
	{
		Log("ERROR: no se pudo crear el socket (error %d)", WSAGetLastError());
		return false;
	}

	// Sin bloqueo: el juego nunca se queda esperando a la red.
	u_long nonBlocking = 1;
	ioctlsocket(g_sock, FIONBIO, &nonBlocking);

	// Evita que Windows reporte errores falsos cuando el otro lado todavia no esta listo.
	DWORD bytes = 0;
	BOOL newBehavior = FALSE;
	WSAIoctl(g_sock, SIO_UDP_CONNRESET, &newBehavior, sizeof(newBehavior), nullptr, 0, &bytes, nullptr, nullptr);

	// El host escucha en el puerto elegido. El client usa cualquier puerto libre.
	sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port = htons(cfg.isHost ? (u_short)cfg.port : (u_short)0);
	if (bind(g_sock, (sockaddr*)&local, sizeof(local)) == SOCKET_ERROR)
	{
		Log("ERROR: no se pudo abrir el puerto %d (error %d). Puede estar ocupado.", cfg.port, WSAGetLastError());
		return false;
	}

	if (!cfg.isHost)
	{
		memset(&g_peer, 0, sizeof(g_peer));
		g_peer.sin_family = AF_INET;
		g_peer.sin_port = htons((u_short)cfg.port);
		if (inet_pton(AF_INET, cfg.ip, &g_peer.sin_addr) != 1)
		{
			Log("ERROR: la ip '%s' del re4coop.ini no es valida", cfg.ip);
			return false;
		}
		g_peerKnown = true;
		Log("Red lista (client): enviando a %s:%d", cfg.ip, cfg.port);
	}
	else
	{
		Log("Red lista (host): esperando al amigo en el puerto %d", cfg.port);
	}
	return true;
}

static void NetSend(const NetPacket& p)
{
	if (!g_peerKnown)
		return;
	sendto(g_sock, (const char*)&p, (int)sizeof(p), 0, (const sockaddr*)&g_peer, (int)sizeof(g_peer));
}

// Lee todos los paquetes que hayan llegado (sin esperar).
static void NetReceive()
{
	for (;;)
	{
		NetPacket p;
		sockaddr_in from;
		int fromLen = (int)sizeof(from);
		int n = recvfrom(g_sock, (char*)&p, (int)sizeof(p), 0, (sockaddr*)&from, &fromLen);
		if (n == SOCKET_ERROR)
			break; // no hay mas paquetes por ahora

		if (n != (int)sizeof(p) || p.magic != NET_MAGIC || p.version != NET_VERSION)
			continue; // paquete que no es nuestro

		// El host aprende la direccion del amigo con su primer paquete.
		if (g_isHost && (!g_peerKnown || !SameAddr(from, g_peer)))
		{
			g_peer = from;
			g_peerKnown = true;
			char text[96];
			AddrToString(from, text, sizeof(text));
			Log("El amigo se conecto desde %s", text);
		}

		if (!g_remote.connected)
			Log(g_remote.everReceived ? "CONEXION RECUPERADA" : "CONECTADO: llegaron datos del amigo");

		g_remote.everReceived = true;
		g_remote.connected = true;
		g_remote.lastRecvTick = GetTickCount();
		g_remote.flags = p.flags;
		memcpy(g_remote.pos, p.pos, sizeof(g_remote.pos));
		g_remote.yaw = p.yaw;
		g_remote.packetsThisSecond++;
	}
}

// Si pasan 3 segundos sin recibir nada, se marca la conexion como perdida.
static void NetCheckTimeout()
{
	if (g_remote.connected && GetTickCount() - g_remote.lastRecvTick > 3000)
	{
		g_remote.connected = false;
		Log("CONEXION PERDIDA: hace mas de 3 segundos que no llegan datos del amigo");
	}
}

// ---------------------------------------------------------------- principal

void ModMain()
{
	LogOpen();
	Log("RE4 Coop - hito 2 iniciado");

	// El .exe de Steam puede tardar unos segundos en dejar su codigo listo,
	// asi que reintentamos hasta 10 veces (cada 3 segundos) antes de rendirnos.
	uintptr_t plGlobal = 0;
	uintptr_t asGlobal = 0;
	for (int attempt = 1; attempt <= 10 && !plGlobal; attempt++)
	{
		Sleep(3000);
		Log("Buscando punteros del juego (intento %d de 10)...", attempt);

		// Patrones tomados de re4_tweaks (Game.cpp). "?" = byte comodin.
		plGlobal = FindGlobalPointer("Leon (pPL)", "A1 ? ? ? ? D8 CC D8 C9 D8 CA D9 5D ? D9 45 ?", 1);
		asGlobal = FindGlobalPointer("Ashley (pAS)", "A8 02 74 16 8B 15", 6);
	}

	if (!plGlobal)
	{
		Log("No se pudo encontrar a Leon. Fin.");
		return;
	}

	// Red: si algo falla, el mod sigue funcionando pero solo anota a Leon (sin conexion).
	bool netOk = false;
	Config cfg;
	if (LoadConfig(cfg))
		netOk = NetInit(cfg);
	if (!netOk)
		Log("AVISO: sin conexion. Revisa re4coop.ini y los mensajes de arriba.");

	bool lastLeonValid = false;
	uint32_t seq = 0;
	DWORD lastLog = GetTickCount();

	for (;;)
	{
		Sleep(50); // 20 veces por segundo

		PlayerInfo leon = {};
		bool leonOk = ReadPlayer(plGlobal, &leon);

		if (netOk)
		{
			NetPacket p = {};
			p.magic = NET_MAGIC;
			p.version = NET_VERSION;
			p.flags = leonOk ? FLAG_IN_GAME : 0;
			p.seq = seq++;
			if (leonOk)
			{
				memcpy(p.pos, leon.pos, sizeof(p.pos));
				p.yaw = leon.angY;
			}
			NetSend(p);
			NetReceive();
			NetCheckTimeout();
		}

		// Una vez por segundo: resumen en el log.
		DWORD now = GetTickCount();
		if (now - lastLog < 1000)
			continue;
		lastLog = now;

		if (leonOk)
		{
			Log("Leon    @0x%08X pos=(%.1f, %.1f, %.1f) giro=%.2f",
				(unsigned)leon.obj, leon.pos[0], leon.pos[1], leon.pos[2], leon.angY);
		}
		else if (lastLeonValid)
		{
			Log("Leon no esta en juego ahora (menu o pantalla de carga)");
		}
		lastLeonValid = leonOk;

		if (asGlobal)
		{
			PlayerInfo ash = {};
			if (ReadPlayer(asGlobal, &ash))
			{
				Log("Ashley  @0x%08X pos=(%.1f, %.1f, %.1f)",
					(unsigned)ash.obj, ash.pos[0], ash.pos[1], ash.pos[2]);
			}
		}

		if (netOk && g_remote.connected)
		{
			Log("AMIGO   %s pos=(%.1f, %.1f, %.1f) giro=%.2f paquetes/s=%d",
				(g_remote.flags & FLAG_IN_GAME) ? "en juego" : "en menu  ",
				g_remote.pos[0], g_remote.pos[1], g_remote.pos[2], g_remote.yaw,
				g_remote.packetsThisSecond);
		}
		g_remote.packetsThisSecond = 0;
	}
}
