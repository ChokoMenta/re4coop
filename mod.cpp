// RE4 Coop - hito 3: el "fantasma" del otro jugador.
//
// Que hace (ademas de lo del hito 2: conexion UDP y envio de la posicion):
//  1. Envia tambien en que sala esta cada jugador (las coordenadas solo valen dentro de la misma sala).
//  2. Engancha la ventana del juego para ejecutar codigo en el hilo principal, ENTRE frames
//     (asi no chocamos con el juego mientras este actualiza sus personajes).
//  3. Con F8 se enciende/apaga el fantasma: un personaje extra, creado con la propia funcion del
//     juego (EmSetEvent, la misma que usa re4_tweaks), que se mueve a donde esta el otro jugador.
//     Por ahora queda congelado (sin animacion ni IA): es un muneco que se desliza.
//  4. Con F9 se cambia el modelo del fantasma (no todos los modelos estan cargados en todas las salas,
//     por eso se puede probar uno por uno).
//
// Los patrones de bytes y las estructuras salen del proyecto re4_tweaks (nipkownix/re4_tweaks, licencia zlib).

// winsock2.h tiene que ir ANTES de windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

// ---------------------------------------------------------------- archivos junto al .exe

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

// Cada linea se escribe y se guarda en el disco enseguida: si el juego se cierra de golpe,
// la ultima linea del log dice que estaba haciendo el mod.
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

// ---------------------------------------------------------------- memoria segura
// Si una direccion es invalida, estas funciones devuelven false en vez de colgar el juego.

static bool SafeRead(uintptr_t addr, void* out, size_t n)
{
	__try
	{
		memcpy(out, (const void*)addr, n);
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
}

static bool SafeWrite(uintptr_t addr, const void* in, size_t n)
{
	__try
	{
		memcpy((void*)addr, in, n);
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
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

// Busca un patron y devuelve la direccion de la instruccion (0 si no se encuentra).
static uintptr_t FindPattern(const char* name, const char* patternText)
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

	Log("OK: %s -> instruccion en 0x%08X", name, (unsigned)addr);
	return addr;
}

// Busca un patron y devuelve el dato de 4 bytes que aparece "offset" bytes despues del inicio
// (por ejemplo, la direccion de una variable global que la instruccion usa).
static uintptr_t FindGlobalPointer(const char* name, const char* patternText, int offset)
{
	uintptr_t addr = FindPattern(name, patternText);
	if (!addr)
		return 0;

	uintptr_t value = 0;
	if (!SafeRead(addr + offset, &value, 4))
		return 0;

	Log("OK: %s -> valor 0x%08X", name, (unsigned)value);
	return value;
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

static bool IsZeroPos(const float* p)
{
	return p[0] == 0.0f && p[1] == 0.0f && p[2] == 0.0f;
}

// ---------------------------------------------------------------- datos globales del juego

static uintptr_t g_plGlobal = 0;  // variable que apunta a Leon
static uintptr_t g_asGlobal = 0;  // variable que apunta a Ashley
static uintptr_t g_pGvar = 0;     // variable que apunta a GLOBAL_WK (datos globales)
static uintptr_t g_emMgr = 0;     // objeto cEmMgr (lista de personajes/enemigos)

// Posiciones dentro de GLOBAL_WK (verificadas por los asserts de tamano de re4_tweaks)
static const uintptr_t G_RNO0 = 0x20;      // 3 = bucle principal del juego (MainLoop)
static const uintptr_t G_ROOM = 0x4FAC;    // curRoomId_4FAC (u16): sala actual
static const uintptr_t G_FRAME = 0x530C;   // frameCounter_530C (u32)
static const uint8_t RNO0_MAINLOOP = 3;

static bool ReadGameState(uint8_t* rno0, uint16_t* room, uint32_t* frame)
{
	uintptr_t g = 0;
	if (!g_pGvar || !SafeRead(g_pGvar, &g, 4) || g < 0x10000)
		return false;

	return SafeRead(g + G_RNO0, rno0, 1) && SafeRead(g + G_ROOM, room, 2) && SafeRead(g + G_FRAME, frame, 4);
}

// ---------------------------------------------------------------- configuracion (re4coop.ini)

struct Config
{
	bool isHost;
	char ip[64];
	int port;
	bool ghostOnStart;     // [fantasma] activo
	int modelId;           // [fantasma] modelo
	bool updateMatrix;     // [fantasma] actualizar_matriz
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

	// Opciones del fantasma (opcionales: si faltan en el .ini se usan estos valores).
	cfg.ghostOnStart = GetPrivateProfileIntA("fantasma", "activo", 0, path) != 0;
	cfg.updateMatrix = GetPrivateProfileIntA("fantasma", "actualizar_matriz", 1, path) != 0;
	char modelText[32];
	GetPrivateProfileStringA("fantasma", "modelo", "0x10", modelText, sizeof(modelText), path);
	cfg.modelId = (int)strtoul(modelText, nullptr, 0);

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

	Log("Configuracion: modo=%s ip='%s' puerto=%d | fantasma: activo=%d modelo=0x%02X matriz=%d",
		cfg.isHost ? "host" : "client", cfg.ip, cfg.port, cfg.ghostOnStart ? 1 : 0, cfg.modelId, cfg.updateMatrix ? 1 : 0);
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
	uint16_t room;    // sala actual del jugador
	uint16_t reserved;
};
#pragma pack(pop)
static_assert(sizeof(NetPacket) == 32, "tamano inesperado del paquete");

static const uint32_t NET_MAGIC = 0x43344552u;
static const uint16_t NET_VERSION = 2; // 2 = incluye la sala
static const uint16_t FLAG_IN_GAME = 1;

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

static SOCKET g_sock = INVALID_SOCKET;
static sockaddr_in g_peer;
static bool g_peerKnown = false;
static bool g_isHost = false;
static bool g_warnedVersion = false;

struct RemoteState
{
	bool everReceived;
	bool connected;
	DWORD lastRecvTick;
	uint16_t flags;
	float pos[3];
	float yaw;
	uint16_t room;
	int packetsThisSecond;
};
static RemoteState g_remote;
static CRITICAL_SECTION g_remoteLock; // el hilo de red escribe, el hilo del juego lee

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

		if (n >= 8 && p.magic == NET_MAGIC && p.version != NET_VERSION)
		{
			if (!g_warnedVersion)
			{
				g_warnedVersion = true;
				Log("AVISO: llegan paquetes de otra version del mod (version %u, esta es la %u). "
					"Los dos tienen que usar el MISMO dinput8.dll.", (unsigned)p.version, (unsigned)NET_VERSION);
			}
			continue;
		}

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

		EnterCriticalSection(&g_remoteLock);
		bool wasConnected = g_remote.connected;
		bool hadReceived = g_remote.everReceived;
		g_remote.everReceived = true;
		g_remote.connected = true;
		g_remote.lastRecvTick = GetTickCount();
		g_remote.flags = p.flags;
		memcpy(g_remote.pos, p.pos, sizeof(g_remote.pos));
		g_remote.yaw = p.yaw;
		g_remote.room = p.room;
		g_remote.packetsThisSecond++;
		LeaveCriticalSection(&g_remoteLock);

		if (!wasConnected)
			Log(hadReceived ? "CONEXION RECUPERADA" : "CONECTADO: llegaron datos del amigo");
	}
}

// Si pasan 3 segundos sin recibir nada, se marca la conexion como perdida.
static void NetCheckTimeout()
{
	bool lost = false;
	EnterCriticalSection(&g_remoteLock);
	if (g_remote.connected && GetTickCount() - g_remote.lastRecvTick > 3000)
	{
		g_remote.connected = false;
		lost = true;
	}
	LeaveCriticalSection(&g_remoteLock);

	if (lost)
		Log("CONEXION PERDIDA: hace mas de 3 segundos que no llegan datos del amigo");
}

// Copia de los datos del amigo, lista para usar en el hilo del juego.
struct RemoteSnap
{
	bool valid;       // conectado, en juego y con posicion real
	float pos[3];
	float yaw;
	uint16_t room;
};

static RemoteSnap GetRemoteSnap()
{
	RemoteSnap s;
	memset(&s, 0, sizeof(s));

	EnterCriticalSection(&g_remoteLock);
	if (g_remote.connected && (g_remote.flags & FLAG_IN_GAME) && !IsZeroPos(g_remote.pos))
	{
		s.valid = true;
		memcpy(s.pos, g_remote.pos, sizeof(s.pos));
		s.yaw = g_remote.yaw;
		s.room = g_remote.room;
	}
	LeaveCriticalSection(&g_remoteLock);
	return s;
}

// ---------------------------------------------------------------- el fantasma

// Modelos que se pueden probar con F9. El primero es el predeterminado.
// (ids de personaje del juego, segun la tabla de re4_tweaks)
// NO se incluyen 0x00 (jugador) ni Ashley (0x03, 0x05, 0x0C): crearlos podria pisar los
// punteros de Leon/Ashley del juego.
struct ModelOpt
{
	uint8_t id;
	const char* name;
};
static const ModelOpt kModels[] = {
	{ 0x10, "Ganado" },
	{ 0x1F, "Soldado" },
	{ 0x02, "Leon (de eventos)" },
	{ 0x04, "Luis" },
	{ 0x39, "Krauser" },
	{ 0x21, "Perro" },
};
static const int kModelMax = 16;
static uint8_t g_modelIds[kModelMax];
static const char* g_modelNames[kModelMax];
static int g_modelCount = 0;
static int g_modelIndex = 0;

static bool IsForbiddenModel(int id)
{
	return id <= 0 || id > 0x61 || id == 0x03 || id == 0x05 || id == 0x0C;
}

static void BuildModelList(int cfgModel)
{
	g_modelCount = 0;

	// Si el .ini pide un modelo que no esta en la lista, va primero.
	bool inList = false;
	for (const ModelOpt& m : kModels)
		if (m.id == cfgModel)
			inList = true;

	if (!inList)
	{
		if (IsForbiddenModel(cfgModel))
			Log("AVISO: modelo=0x%02X del .ini no esta permitido, se usa 0x10", cfgModel);
		else
		{
			g_modelIds[g_modelCount] = (uint8_t)cfgModel;
			g_modelNames[g_modelCount] = "personalizado (.ini)";
			g_modelCount++;
		}
	}

	for (const ModelOpt& m : kModels)
	{
		if (g_modelCount >= kModelMax)
			break;
		g_modelIds[g_modelCount] = m.id;
		g_modelNames[g_modelCount] = m.name;
		g_modelCount++;
	}

	// Empezar por el modelo pedido en el .ini.
	g_modelIndex = 0;
	for (int i = 0; i < g_modelCount; i++)
		if (g_modelIds[i] == cfgModel)
			g_modelIndex = i;
}

// Funcion del juego que crea un personaje a partir de una estructura EM_LIST (0x20 bytes).
// Se llama igual que lo hace el propio juego: cdecl, un solo parametro.
typedef void* (__cdecl* EmSetEvent_t)(void* emList);
static EmSetEvent_t g_EmSetEvent = nullptr;

// Estructura EM_LIST (misma disposicion que em_set.h de re4_tweaks).
// Esta fuera de la pila a proposito: el juego podria guardar el puntero.
static uint8_t g_emList[0x20];

// Posiciones dentro de cEm (verificadas por los asserts de tamano de re4_tweaks)
static const uintptr_t EM_FLAGS = 0x04;     // cUnit::be_flag_4
static const uintptr_t EM_POS = 0x94;       // cCoord::pos_94
static const uintptr_t EM_ANG_Y = 0xA4;     // cCoord::ang_A0.y
static const uintptr_t EM_GUID = 0xF8;      // cModel::guid_F8
static const uintptr_t EM_RNO0 = 0xFC;      // cModel::r_no_0_FC (0 = Init)
static const uintptr_t EM_ID = 0x100;       // cModel::id_100
static const uint32_t FLAG_VALID_MASK = 0x601; // cEm::IsValid
static const uint32_t FLAG_MOVE = 0x20;
static const uint32_t FLAG_DESTRUCT = 0x400;

struct Ghost
{
	uintptr_t em;
	uint32_t guid;
	uint8_t id;
	int frames;        // frames desde que se creo
	bool frozen;       // ya se le quito el movimiento propio
	bool havePos;
	float pos[3];
	float yaw;
};
static Ghost g_ghost;

static bool g_ghostEnabled = false;
static bool g_updateMatrix = true;
static int g_spawnFails = 0;
static DWORD g_holdUntil = 0;
static uint16_t g_lastRoom = 0xFFFF;

static bool SafeSpawn(void* list, uintptr_t* outEm)
{
	__try
	{
		*outEm = (uintptr_t)g_EmSetEvent(list);
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
}

// cCoord::matUpdate es el primer metodo virtual despues de los de cUnit (destructor, beginEvent, endEvent).
typedef void(__thiscall* ThisCall0_t)(void* self);
static bool SafeMatUpdate(uintptr_t em)
{
	__try
	{
		void** vtbl = *(void***)em;
		ThisCall0_t fn = (ThisCall0_t)vtbl[3];
		fn((void*)em);
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
}

// ?El puntero del fantasma sigue siendo un personaje vivo del juego?
// (el juego destruye a todos los personajes al cambiar de sala)
static bool GhostValid()
{
	if (!g_ghost.em || !g_emMgr)
		return false;

	uint32_t arr = 0, n = 0, size = 0;
	if (!SafeRead(g_emMgr + 4, &arr, 4) || !SafeRead(g_emMgr + 8, &n, 4) || !SafeRead(g_emMgr + 0xC, &size, 4))
		return false;
	if (arr == 0 || size == 0 || n == 0 || n > 4096)
		return false;

	uintptr_t em = g_ghost.em;
	if (em < arr || em >= (uintptr_t)arr + (uintptr_t)n * size || (em - arr) % size != 0)
		return false;

	uint32_t flags = 0, guid = 0;
	uint8_t id = 0;
	if (!SafeRead(em + EM_FLAGS, &flags, 4) || !SafeRead(em + EM_GUID, &guid, 4) || !SafeRead(em + EM_ID, &id, 1))
		return false;

	return (flags & FLAG_VALID_MASK) != 0 && id == g_ghost.id && guid == g_ghost.guid;
}

// Pide al juego que destruya al fantasma (el juego lo hace en su proxima limpieza).
static void GhostDespawn()
{
	if (g_ghost.em && GhostValid())
	{
		uint32_t flags = 0;
		if (SafeRead(g_ghost.em + EM_FLAGS, &flags, 4))
		{
			flags |= FLAG_DESTRUCT;
			SafeWrite(g_ghost.em + EM_FLAGS, &flags, 4);
		}
		Log("Fantasma eliminado");
	}
	memset(&g_ghost, 0, sizeof(g_ghost));
}

static void PutShort(uint8_t* base, int offset, int value)
{
	if (value > 32767) value = 32767;
	if (value < -32768) value = -32768;
	int16_t v = (int16_t)value;
	memcpy(base + offset, &v, 2);
}

static void GhostSpawn(const RemoteSnap& snap, uint16_t room)
{
	uint8_t id = g_modelIds[g_modelIndex];
	Log("Creando fantasma: modelo 0x%02X (%s) en sala 0x%04X ...", id, g_modelNames[g_modelIndex], room);

	// Armamos la estructura EM_LIST.
	memset(g_emList, 0, sizeof(g_emList));
	g_emList[0] = 0x01;          // be_flag_0: vivo
	g_emList[1] = id;            // id_1: que personaje
	int16_t hp = 1000;
	memcpy(g_emList + 0x08, &hp, 2);
	// Posicion: el juego guarda las posiciones del archivo ESL en shorts (aprox. mundo / 10).
	// Es solo la posicion inicial: despues la fijamos nosotros cada frame.
	PutShort(g_emList, 0x0C, (int)(snap.pos[0] / 10.0f));
	PutShort(g_emList, 0x0E, (int)(snap.pos[1] / 10.0f));
	PutShort(g_emList, 0x10, (int)(snap.pos[2] / 10.0f));
	memcpy(g_emList + 0x18, &room, 2); // room_18

	uintptr_t em = 0;
	if (!SafeSpawn(g_emList, &em))
	{
		Log("ERROR: el juego dio una excepcion al crear el modelo 0x%02X", id);
		g_spawnFails++;
		g_holdUntil = GetTickCount() + 2000;
		return;
	}
	Log("EmSetEvent devolvio 0x%08X", (unsigned)em);

	// Comprobamos que el resultado sea un personaje valido de la lista del juego.
	memset(&g_ghost, 0, sizeof(g_ghost));
	g_ghost.em = em;
	g_ghost.id = id;
	uint32_t guid = 0;
	uint8_t realId = 0;
	if (em == 0 || !SafeRead(em + EM_GUID, &guid, 4) || !SafeRead(em + EM_ID, &realId, 1))
	{
		Log("ERROR: el resultado no es un personaje valido (el modelo 0x%02X seguramente no esta cargado en esta sala)", id);
		memset(&g_ghost, 0, sizeof(g_ghost));
		g_spawnFails++;
		g_holdUntil = GetTickCount() + 2000;
		return;
	}
	g_ghost.guid = guid;
	g_ghost.id = realId;
	if (realId != id)
		Log("AVISO: pedi el modelo 0x%02X pero el juego devolvio 0x%02X", id, realId);

	if (!GhostValid())
	{
		Log("ERROR: el personaje creado no figura como vivo en la lista del juego");
		memset(&g_ghost, 0, sizeof(g_ghost));
		g_spawnFails++;
		g_holdUntil = GetTickCount() + 2000;
		return;
	}

	uint32_t flags = 0;
	uint8_t rno0 = 0;
	SafeRead(em + EM_FLAGS, &flags, 4);
	SafeRead(em + EM_RNO0, &rno0, 1);
	Log("Fantasma CREADO: em=0x%08X guid=%u flags=0x%X r_no_0=%u", (unsigned)em, (unsigned)guid, (unsigned)flags, (unsigned)rno0);

	memcpy(g_ghost.pos, snap.pos, sizeof(g_ghost.pos));
	g_ghost.yaw = snap.yaw;
	g_ghost.havePos = true;
	g_spawnFails = 0;
}

static float AngleDiff(float a, float b)
{
	const float PI = 3.14159265f;
	float d = a - b;
	while (d > PI) d -= 2.0f * PI;
	while (d < -PI) d += 2.0f * PI;
	return d;
}

// Mueve al fantasma hacia la posicion del amigo, suavizando entre los paquetes (llegan 20 por segundo).
static void GhostMove(const RemoteSnap& snap, float dt)
{
	g_ghost.frames++;

	// Cuando el personaje termino de inicializarse, le quitamos el movimiento propio (IA/animacion).
	if (!g_ghost.frozen)
	{
		uint8_t rno0 = 0;
		uint32_t flags = 0;
		if (SafeRead(g_ghost.em + EM_RNO0, &rno0, 1) && SafeRead(g_ghost.em + EM_FLAGS, &flags, 4))
		{
			if (rno0 != 0)
			{
				flags &= ~FLAG_MOVE;
				SafeWrite(g_ghost.em + EM_FLAGS, &flags, 4);
				g_ghost.frozen = true;
				Log("Fantasma congelado (inicializado tras %d frames, r_no_0=%u)", g_ghost.frames, (unsigned)rno0);
			}
			else if (g_ghost.frames > 60)
			{
				g_ghost.frozen = true;
				Log("AVISO: el fantasma no termino de inicializarse en 60 frames; se deja con su movimiento propio");
			}
		}
	}

	// Suavizado de posicion (o salto directo si esta muy lejos).
	float dx = snap.pos[0] - g_ghost.pos[0];
	float dy = snap.pos[1] - g_ghost.pos[1];
	float dz = snap.pos[2] - g_ghost.pos[2];
	float dist2 = dx * dx + dy * dy + dz * dz;
	if (dist2 > 3000.0f * 3000.0f)
	{
		memcpy(g_ghost.pos, snap.pos, sizeof(g_ghost.pos));
		g_ghost.yaw = snap.yaw;
	}
	else
	{
		float alpha = 1.0f - expf(-dt * 18.0f);
		g_ghost.pos[0] += dx * alpha;
		g_ghost.pos[1] += dy * alpha;
		g_ghost.pos[2] += dz * alpha;
		g_ghost.yaw += AngleDiff(snap.yaw, g_ghost.yaw) * alpha;
	}

	SafeWrite(g_ghost.em + EM_POS, g_ghost.pos, sizeof(g_ghost.pos));
	SafeWrite(g_ghost.em + EM_ANG_Y, &g_ghost.yaw, sizeof(g_ghost.yaw));

	if (g_updateMatrix && !SafeMatUpdate(g_ghost.em))
	{
		g_updateMatrix = false;
		Log("AVISO: fallo la actualizacion de la matriz del fantasma; se desactiva (actualizar_matriz=0)");
	}
}

// ---------------------------------------------------------------- ejecucion en el hilo del juego

// Mensaje propio que el hilo de red le manda a la ventana del juego. Como el juego procesa sus
// mensajes en su hilo principal y entre frames, el codigo de GameTick corre ahi, de forma segura.
static const UINT WM_COOP_TICK = WM_APP + 0x4C;

static HWND g_hwnd = nullptr;
static WNDPROC g_origProc = nullptr;
static bool g_wndUnicode = false;
static volatile LONG g_tickPending = 0;

static DWORD g_gameThreadId = 0;
static int g_tickCount = 0;       // ticks desde el ultimo resumen del log
static int g_tickFaults = 0;

static bool g_f8Prev = false;
static bool g_f9Prev = false;

static void HandleHotkeys()
{
	// Solo cuando la ventana del juego tiene el foco (si no, escribir en otra ventana activaria cosas).
	bool focused = (GetForegroundWindow() == g_hwnd);
	bool f8 = focused && (GetAsyncKeyState(VK_F8) & 0x8000) != 0;
	bool f9 = focused && (GetAsyncKeyState(VK_F9) & 0x8000) != 0;

	if (f8 && !g_f8Prev)
	{
		g_ghostEnabled = !g_ghostEnabled;
		g_spawnFails = 0;
		Log("F8: fantasma %s", g_ghostEnabled ? "ACTIVADO" : "DESACTIVADO");
		MessageBeep(g_ghostEnabled ? MB_ICONASTERISK : MB_ICONHAND);
		if (!g_ghostEnabled)
			GhostDespawn();
	}

	if (f9 && !g_f9Prev)
	{
		g_modelIndex = (g_modelIndex + 1) % g_modelCount;
		g_spawnFails = 0;
		Log("F9: modelo del fantasma = 0x%02X (%s)", g_modelIds[g_modelIndex], g_modelNames[g_modelIndex]);
		MessageBeep(MB_OK);
		GhostDespawn();
	}

	g_f8Prev = f8;
	g_f9Prev = f9;
}

static void GhostUpdate(float dt)
{
	uint8_t rno0 = 0;
	uint16_t room = 0;
	uint32_t frame = 0;
	DWORD now = GetTickCount();

	if (!ReadGameState(&rno0, &room, &frame))
		return;

	// Al cambiar de sala (o mientras el juego no esta en su bucle principal) esperamos un poco
	// antes de crear nada: el juego esta cargando y destruyendo personajes.
	if (room != g_lastRoom || rno0 != RNO0_MAINLOOP)
		g_holdUntil = now + 2000;
	if (room != g_lastRoom && g_ghost.em)
	{
		Log("Cambio de sala 0x%04X -> 0x%04X: se descarta el fantasma", g_lastRoom, room);
		GhostDespawn();
	}
	g_lastRoom = room;

	// ?Hay que mostrar al fantasma ahora mismo?
	RemoteSnap snap = GetRemoteSnap();
	PlayerInfo leon = {};
	bool leonOk = ReadPlayer(g_plGlobal, &leon) && !IsZeroPos(leon.pos);
	bool wanted = g_ghostEnabled && snap.valid && leonOk && rno0 == RNO0_MAINLOOP && room != 0 && snap.room == room;

	if (!wanted)
	{
		if (g_ghost.em)
			GhostDespawn();
		return;
	}

	// ?El juego se llevo al fantasma sin avisar?
	if (g_ghost.em && !GhostValid())
	{
		Log("El juego elimino al fantasma (hay que crearlo de nuevo)");
		memset(&g_ghost, 0, sizeof(g_ghost));
		g_holdUntil = now + 1000;
	}

	if (!g_ghost.em)
	{
		if ((int)(now - g_holdUntil) < 0)
			return;
		if (g_spawnFails >= 3)
		{
			if (g_spawnFails == 3)
			{
				Log("Demasiados intentos fallidos: se deja de intentar. Proba otro modelo con F9.");
				g_spawnFails++;
			}
			return;
		}
		GhostSpawn(snap, room);
		return;
	}

	GhostMove(snap, dt);
}

static void GameTick()
{
	if (!g_gameThreadId)
	{
		g_gameThreadId = GetCurrentThreadId();
		DWORD wndThread = GetWindowThreadProcessId(g_hwnd, nullptr);
		Log("Primer tick en el hilo %lu (hilo de la ventana: %lu)", (unsigned long)g_gameThreadId, (unsigned long)wndThread);
	}
	g_tickCount++;

	// Tiempo desde el tick anterior (para suavizar el movimiento).
	static LARGE_INTEGER freq = {};
	static LARGE_INTEGER last = {};
	LARGE_INTEGER nowQpc;
	QueryPerformanceCounter(&nowQpc);
	if (freq.QuadPart == 0)
		QueryPerformanceFrequency(&freq);
	float dt = 0.016f;
	if (last.QuadPart != 0 && freq.QuadPart != 0)
		dt = (float)((double)(nowQpc.QuadPart - last.QuadPart) / (double)freq.QuadPart);
	last = nowQpc;
	if (dt < 0.0f) dt = 0.0f;
	if (dt > 0.1f) dt = 0.1f;

	HandleHotkeys();
	GhostUpdate(dt);
}

// Por si algo falla dentro del tick: el juego no se cae, y queda anotado en el log.
static void GameTickSafe()
{
	__try
	{
		GameTick();
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		g_tickFaults++;
		if (g_tickFaults <= 5)
			Log("ERROR: excepcion dentro del tick del juego (#%d)", g_tickFaults);
	}
}

static LRESULT CALLBACK GameWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (msg == WM_COOP_TICK)
	{
		InterlockedExchange(&g_tickPending, 0);
		GameTickSafe();
		return 0;
	}

	if (!g_origProc)
		return g_wndUnicode ? DefWindowProcW(hwnd, msg, wParam, lParam) : DefWindowProcA(hwnd, msg, wParam, lParam);

	if (g_wndUnicode)
		return CallWindowProcW(g_origProc, hwnd, msg, wParam, lParam);
	return CallWindowProcA(g_origProc, hwnd, msg, wParam, lParam);
}

struct FindWin
{
	DWORD pid;
	HWND best;
	long bestArea;
};

static BOOL CALLBACK EnumWinProc(HWND hwnd, LPARAM lParam)
{
	FindWin* f = (FindWin*)lParam;

	DWORD pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);
	if (pid != f->pid || !IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER) != nullptr)
		return TRUE;

	RECT r;
	if (!GetWindowRect(hwnd, &r))
		return TRUE;

	long area = (r.right - r.left) * (r.bottom - r.top);
	if (area > f->bestArea)
	{
		f->bestArea = area;
		f->best = hwnd;
	}
	return TRUE;
}

// Busca la ventana del juego y le "engancha" nuestro procedimiento de mensajes.
static bool HookGameWindow()
{
	FindWin f = {};
	f.pid = GetCurrentProcessId();
	EnumWindows(EnumWinProc, (LPARAM)&f);
	if (!f.best)
	{
		Log("ERROR: no se encontro la ventana del juego");
		return false;
	}

	g_hwnd = f.best;
	char cls[128] = "?";
	GetClassNameA(g_hwnd, cls, sizeof(cls));
	g_wndUnicode = IsWindowUnicode(g_hwnd) != FALSE;

	// Primero guardamos el procedimiento original y recien despues lo reemplazamos: asi, si el juego
	// recibe un mensaje justo en el medio, GameWndProc ya sabe a quien reenviarlo.
	LONG_PTR cur = g_wndUnicode ? GetWindowLongPtrW(g_hwnd, GWLP_WNDPROC) : GetWindowLongPtrA(g_hwnd, GWLP_WNDPROC);
	if (!cur)
	{
		Log("ERROR: no se pudo leer el procedimiento de la ventana del juego (error %lu)", (unsigned long)GetLastError());
		g_hwnd = nullptr;
		return false;
	}
	g_origProc = (WNDPROC)cur;

	LONG_PTR prev;
	if (g_wndUnicode)
		prev = SetWindowLongPtrW(g_hwnd, GWLP_WNDPROC, (LONG_PTR)GameWndProc);
	else
		prev = SetWindowLongPtrA(g_hwnd, GWLP_WNDPROC, (LONG_PTR)GameWndProc);

	if (!prev)
	{
		Log("ERROR: no se pudo enganchar la ventana del juego (error %lu)", (unsigned long)GetLastError());
		g_origProc = nullptr;
		g_hwnd = nullptr;
		return false;
	}

	Log("OK: ventana del juego enganchada (clase '%s', hilo de la ventana %lu, unicode=%d)",
		cls, (unsigned long)GetWindowThreadProcessId(g_hwnd, nullptr), g_wndUnicode ? 1 : 0);
	return true;
}

// ---------------------------------------------------------------- principal

static uint16_t ReadRoomNow()
{
	uint8_t rno0 = 0;
	uint16_t room = 0;
	uint32_t frame = 0;
	if (!ReadGameState(&rno0, &room, &frame))
		return 0;
	return room;
}

void ModMain()
{
	LogOpen();
	Log("RE4 Coop - hito 3 iniciado");
	InitializeCriticalSection(&g_remoteLock);

	// El .exe de Steam puede tardar unos segundos en dejar su codigo listo,
	// asi que reintentamos hasta 10 veces (cada 3 segundos) antes de rendirnos.
	for (int attempt = 1; attempt <= 10 && !g_plGlobal; attempt++)
	{
		Sleep(3000);
		Log("Buscando punteros del juego (intento %d de 10)...", attempt);

		// Patrones tomados de re4_tweaks (Game.cpp). "?" = byte comodin.
		g_plGlobal = FindGlobalPointer("Leon (pPL)", "A1 ? ? ? ? D8 CC D8 C9 D8 CA D9 5D ? D9 45 ?", 1);
		g_asGlobal = FindGlobalPointer("Ashley (pAS)", "A8 02 74 16 8B 15", 6);
		g_pGvar = FindGlobalPointer("Datos globales (pG)", "A1 ? ? ? ? B9 FF FF FF 7F 21 48 ? A1", 1);
		g_emMgr = FindGlobalPointer("Lista de personajes (EmMgr)", "81 E1 01 02 00 00 83 F9 01 75 ? 50 B9 ? ? ? ? E8", 0xD);
	}

	if (!g_plGlobal)
	{
		Log("No se pudo encontrar a Leon. Fin.");
		return;
	}

	// Funcion que crea personajes: el patron cae dentro de una funcion que la llama (instruccion E8 en +9).
	uintptr_t spawnCaller = FindPattern("EmSetEvent (llamada)", "52 66 89 45 E4 66 89 4D F6 E8");
	if (spawnCaller)
	{
		int32_t rel = 0;
		if (SafeRead(spawnCaller + 10, &rel, 4))
		{
			g_EmSetEvent = (EmSetEvent_t)(spawnCaller + 9 + 5 + rel);
			Log("OK: EmSetEvent en 0x%08X", (unsigned)(uintptr_t)g_EmSetEvent);
		}
	}

	bool ghostPossible = g_pGvar && g_emMgr && g_EmSetEvent;
	if (!ghostPossible)
		Log("AVISO: faltan datos del juego (pG=%d EmMgr=%d EmSetEvent=%d): el fantasma no estara disponible.",
			g_pGvar ? 1 : 0, g_emMgr ? 1 : 0, g_EmSetEvent ? 1 : 0);

	// Red: si algo falla, el mod sigue funcionando pero solo anota a Leon (sin conexion).
	bool netOk = false;
	Config cfg;
	bool cfgOk = LoadConfig(cfg);
	if (cfgOk)
		netOk = NetInit(cfg);
	if (!netOk)
		Log("AVISO: sin conexion. Revisa re4coop.ini y los mensajes de arriba.");

	// Fantasma: lista de modelos y enganche de la ventana.
	int cfgModel = cfgOk ? cfg.modelId : 0x10;
	BuildModelList(cfgModel);
	g_updateMatrix = cfgOk ? cfg.updateMatrix : true;
	g_ghostEnabled = cfgOk && cfg.ghostOnStart && ghostPossible;
	Log("Modelo inicial del fantasma: 0x%02X (%s). Teclas: F8 = activar/desactivar, F9 = cambiar modelo.",
		g_modelIds[g_modelIndex], g_modelNames[g_modelIndex]);

	bool hooked = false;
	if (ghostPossible)
	{
		for (int attempt = 1; attempt <= 10 && !hooked; attempt++)
		{
			hooked = HookGameWindow();
			if (!hooked)
				Sleep(2000);
		}
	}

	bool lastLeonValid = false;
	uint32_t seq = 0;
	DWORD lastNet = GetTickCount();
	DWORD lastLog = GetTickCount();
	DWORD lastTickPost = 0;
	uint32_t lastFrame = 0;

	for (;;)
	{
		Sleep(2);
		DWORD now = GetTickCount();

		// Le pedimos al juego que ejecute un tick (en su hilo). Solo uno a la vez: si el juego
		// todavia no proceso el anterior, no acumulamos mensajes.
		if (hooked && g_tickPending == 0 && now - lastTickPost >= 4)
		{
			InterlockedExchange(&g_tickPending, 1);
			if (!PostMessageA(g_hwnd, WM_COOP_TICK, 0, 0))
				InterlockedExchange(&g_tickPending, 0);
			lastTickPost = now;
		}

		// Red: 20 veces por segundo.
		PlayerInfo leon = {};
		bool leonOk = false;
		if (netOk && now - lastNet >= 50)
		{
			lastNet = now;
			leonOk = ReadPlayer(g_plGlobal, &leon);
			bool inGame = leonOk && !IsZeroPos(leon.pos);

			NetPacket p = {};
			p.magic = NET_MAGIC;
			p.version = NET_VERSION;
			p.flags = inGame ? FLAG_IN_GAME : 0;
			p.seq = seq++;
			p.room = ReadRoomNow();
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
		if (now - lastLog < 1000)
			continue;
		lastLog = now;

		leonOk = ReadPlayer(g_plGlobal, &leon);
		if (leonOk)
		{
			Log("Leon    @0x%08X pos=(%.1f, %.1f, %.1f) giro=%.2f sala=0x%04X",
				(unsigned)leon.obj, leon.pos[0], leon.pos[1], leon.pos[2], leon.angY, (unsigned)ReadRoomNow());
		}
		else if (lastLeonValid)
		{
			Log("Leon no esta en juego ahora (menu o pantalla de carga)");
		}
		lastLeonValid = leonOk;

		if (g_asGlobal)
		{
			PlayerInfo ash = {};
			if (ReadPlayer(g_asGlobal, &ash))
			{
				Log("Ashley  @0x%08X pos=(%.1f, %.1f, %.1f)",
					(unsigned)ash.obj, ash.pos[0], ash.pos[1], ash.pos[2]);
			}
		}

		if (netOk)
		{
			EnterCriticalSection(&g_remoteLock);
			RemoteState r = g_remote;
			g_remote.packetsThisSecond = 0;
			LeaveCriticalSection(&g_remoteLock);

			if (r.connected)
			{
				Log("AMIGO   %s pos=(%.1f, %.1f, %.1f) giro=%.2f sala=0x%04X paquetes/s=%d",
					(r.flags & FLAG_IN_GAME) ? "en juego" : "en menu  ",
					r.pos[0], r.pos[1], r.pos[2], r.yaw, (unsigned)r.room, r.packetsThisSecond);
			}
		}

		if (hooked)
		{
			uint8_t rno0 = 0;
			uint16_t room = 0;
			uint32_t frame = 0;
			ReadGameState(&rno0, &room, &frame);
			if (lastFrame == 0)
				lastFrame = frame;
			Log("ESTADO  ticks=%d frames=%u fantasma=%s%s modelo=0x%02X rno0=%u",
				g_tickCount, (unsigned)(frame - lastFrame),
				g_ghostEnabled ? "ON" : "off", g_ghost.em ? " (creado)" : "",
				g_modelIds[g_modelIndex], (unsigned)rno0);
			lastFrame = frame;
			g_tickCount = 0;
		}
	}
}
