// RE4 Coop - hito 3b: el "fantasma" del otro jugador (version segura).
//
// Que hace (ademas de lo del hito 2: conexion UDP y envio de la posicion):
//  1. Envia tambien en que sala esta cada jugador (las coordenadas solo valen dentro de la misma sala).
//  2. Engancha la ventana del juego para ejecutar codigo en el hilo principal, ENTRE frames
//     (asi no chocamos con el juego mientras este actualiza sus personajes).
//  3. Con F8 se enciende/apaga el fantasma: un personaje extra, creado con la propia funcion del
//     juego (EmSetEvent, la misma que usa re4_tweaks), que se mueve a donde esta el otro jugador.
//     Por ahora queda congelado (sin animacion ni IA): es un muneco que se desliza.
//  4. Con F9 se cambia el modelo del fantasma.
//
// Cambio del hito 3b: en el hito 3 el juego se colgo al pedirle un modelo que no estaba cargado en la sala.
// Ahora el mod SOLO crea el modelo de un enemigo que ya esta vivo en la sala, y arma la estructura
// copiando la entrada real de ese enemigo en la lista de la sala. F9 cambia entre esos modelos disponibles.
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

// Mientras el juego carga, la posicion de Leon puede ser cero o valores minimos (en los logs del hito 3
// aparecio "en juego" con pos=(0.0, 0.0, 0.0)): todo lo que este practicamente en el origen no cuenta.
static bool IsZeroPos(const float* p)
{
	return fabsf(p[0]) < 1.0f && fabsf(p[1]) < 1.0f && fabsf(p[2]) < 1.0f;
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

// Vida de Leon (esta en los datos globales, no en el personaje).
static bool ReadPlayerHp(int16_t* cur, int16_t* mx)
{
	uintptr_t g = 0;
	if (!g_pGvar || !SafeRead(g_pGvar, &g, 4) || g < 0x10000)
		return false;
	return SafeRead(g + 0x4FB4, cur, 2) && SafeRead(g + 0x4FB6, mx, 2);   // playerHpCur_4FB4 / playerHpMax_4FB6
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
	bool killOnHang;       // [fantasma] cerrar_si_se_cuelga
	bool leonClone;        // [fantasma] tipo = leon (clon de Leon, sin necesitar enemigos) o ganado
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
	cfg.killOnHang = GetPrivateProfileIntA("fantasma", "cerrar_si_se_cuelga", 1, path) != 0;
	{
		char tipo[32];
		GetPrivateProfileStringA("fantasma", "tipo", "leon", tipo, sizeof(tipo), path);
		cfg.leonClone = _stricmp(tipo, "ganado") != 0;
	}
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

	Log("Configuracion: modo=%s ip='%s' puerto=%d | fantasma: tipo=%s activo=%d modelo=0x%02X matriz=%d cerrar_si_se_cuelga=%d",
		cfg.isHost ? "host" : "client", cfg.ip, cfg.port, cfg.leonClone ? "leon" : "ganado", cfg.ghostOnStart ? 1 : 0, cfg.modelId, cfg.updateMatrix ? 1 : 0,
		cfg.killOnHang ? 1 : 0);
	return true;
}

// ---------------------------------------------------------------- red (UDP)

#pragma pack(push, 1)
// 3w: estado de animacion de Leon. Los punteros son distintos en cada PC, asi que se mandan como distancia
// a un punto de referencia (la tabla de movimientos del jugador) y un hash de los primeros bytes del clip para verificar.
struct MotPart
{
	int32_t dFcv, dHerm, dJno, dJkind; // puntero - referencia
	uint32_t hash;      // hash de 32 bytes del clip (verifica que el receptor encontro el mismo clip)
	float frameMax, frame, speed;
	uint16_t attr, state;
	uint32_t flag;
	int16_t tblIdx;     // indice del clip en la tabla de movimientos (-1 = no esta)
	uint8_t tblSel;     // 0 = tabla +0x46C, 1 = tabla +0x470
	uint8_t jointNum;
	uint8_t valid;
	uint8_t pad[3];
};
struct NetPacket
{
	uint32_t magic;   // numero fijo para reconocer nuestros paquetes
	uint16_t version;
	uint16_t flags;   // bit 0: Leon esta en juego (no en menu/carga)
	uint32_t seq;     // numero de paquete
	float pos[3];
	float yaw;
	uint16_t room;    // sala actual del jugador
	uint16_t echoDelay; // ms que pasaron desde que recibi tickSend del otro hasta que mande este paquete (para el ping)
	uint32_t tickSend;  // mi reloj (GetTickCount) al enviar este paquete
	uint32_t echoTick;  // el tickSend del ultimo paquete que recibi del otro (0 = ninguno todavia)
	MotPart mot;
	MotPart sub;      // 3y: segunda capa de animacion (cPlayer+0x474: parte de arriba del cuerpo al apuntar, etc.)
};
#pragma pack(pop)
static_assert(sizeof(MotPart) == 48, "tamano inesperado de MotPart");
static_assert(sizeof(NetPacket) == 136, "tamano inesperado del paquete");

static const uint32_t NET_MAGIC = 0x43344552u;
static const uint16_t NET_VERSION = 5; // 4 = incluye la animacion de Leon (3 = ping)
static const uint16_t FLAG_IN_GAME = 1;

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

static SOCKET g_sock = INVALID_SOCKET;
static sockaddr_in g_peer;
static bool g_peerKnown = false;
static bool g_isHost = false;
static bool g_warnedVersion = false;
static bool g_netOk = false;   // la red esta funcionando (la maneja el hilo de red; el panel F7 pide cambios con g_req)

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
	uint32_t theirTick;       // ultimo tickSend recibido del otro
	DWORD theirTickAt;        // cuando lo recibi (mi reloj)
	int pingMs;               // ping suavizado en ms (-1 = todavia no se pudo medir)
	DWORD firstConnectTick;   // cuando se conecto por primera vez en esta sesion de red
	char peerText[48];        // direccion del otro jugador, para mostrar
	MotPart mot;              // 3w: animacion del otro
	MotPart sub;              // 3y: segunda capa
	uint32_t motStamp;        // sube con cada paquete recibido
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

static void NetStop()
{
	if (g_sock != INVALID_SOCKET)
	{
		closesocket(g_sock);
		g_sock = INVALID_SOCKET;
	}
	g_peerKnown = false;
	g_netOk = false;
	EnterCriticalSection(&g_remoteLock);
	memset(&g_remote, 0, sizeof(g_remote));
	LeaveCriticalSection(&g_remoteLock);
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
		g_remote.mot = p.mot;
		g_remote.sub = p.sub;
		g_remote.motStamp++;
		g_remote.packetsThisSecond++;
		{
			DWORD nowTick = GetTickCount();
			g_remote.theirTick = p.tickSend;
			g_remote.theirTickAt = nowTick;
			if (!hadReceived)
			{
				g_remote.firstConnectTick = nowTick;
				g_remote.pingMs = -1;
				AddrToString(from, g_remote.peerText, sizeof(g_remote.peerText));
			}
			if (p.echoTick != 0)
			{
				uint32_t rtt = (uint32_t)nowTick - p.echoTick - (uint32_t)p.echoDelay;
				if (rtt < 5000)
					g_remote.pingMs = (g_remote.pingMs < 0) ? (int)rtt : (g_remote.pingMs * 3 + (int)rtt) / 4;
			}
		}
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
	MotPart mot;
	MotPart sub;
	uint32_t motStamp;
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
		s.mot = g_remote.mot;
		s.sub = g_remote.sub;
		s.motStamp = g_remote.motStamp;
	}
	LeaveCriticalSection(&g_remoteLock);
	return s;
}

// ---------------------------------------------------------------- el fantasma

// Modelos que el mod acepta para el fantasma (ids de personaje del juego, segun la tabla de re4_tweaks):
// solo personajes humanoides comunes. Quedan afuera el jugador (0x00), Ashley (0x03, 0x05, 0x0C: crearla
// podria pisar los punteros de Ashley del juego), los jefes, los comerciantes y los vehiculos.
// Aun estando en esta lista, un modelo solo se usa si ya hay un enemigo igual vivo en la sala.
struct ModelInfo
{
	uint8_t id;
	const char* name;
};
static const ModelInfo kAllowed[] = {
	{ 0x10, "Ganado" },
	{ 0x11, "Zealot" },
	{ 0x12, "Ganado" },
	{ 0x15, "Ganado" },
	{ 0x16, "Ganado" },
	{ 0x17, "Ganado" },
	{ 0x19, "Zealot" },
	{ 0x1A, "Zealot" },
	{ 0x1F, "Soldado" },
	{ 0x42, "Ganado (Separate Ways)" },
	{ 0x43, "Soldado (Separate Ways)" },
	{ 0x44, "Ganado (Separate Ways)" },
	{ 0x02, "Leon (de eventos)" },
	{ 0x04, "Luis" },
};

static bool IsAllowedModel(int id)
{
	for (const ModelInfo& m : kAllowed)
		if (m.id == id)
			return true;
	return false;
}

static const char* ModelName(int id)
{
	for (const ModelInfo& m : kAllowed)
		if (m.id == id)
			return m.name;
	return "?";
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
static const uint32_t FLAG_DISABLEMOTION = 0x4000; // UNIT_BE_FLAG_DISABLEMOTION
static const uint32_t FLAG_DESTRUCT = 0x400;

struct Ghost
{
	uintptr_t em;
	uint32_t guid;
	uint8_t id;
	int frames;        // frames desde que se creo
	bool frozen;       // ya se le quito el movimiento propio
	bool isClone;      // es un clon de Leon (prueba de skin): se congela a los 2 frames, sin esperar a r_no_0
	bool pinSet;       // modo 3: ya se guardo la rutina a mantener
	uint8_t pinR[3];   // modo 3: r_no_1, r_no_2, r_no_3 a mantener
	int reFrozen;      // veces que el juego le volvio a activar el movimiento y se lo quitamos de nuevo
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

// ---- modelos disponibles en la sala ----
// Una "candidata" es un enemigo que YA esta vivo en la sala: si existe, su modelo esta cargado y se puede
// crear otro igual sin riesgo. De ese enemigo se copia su entrada en la lista de la sala (GLOBAL_WK::Em_list_5410:
// 256 entradas de 0x20 bytes), que es una estructura EM_LIST completa y valida.
static const uintptr_t EM_LISTIDX = 0x3A0;   // cEm::emListIndex_3A0 (255 = no viene de la lista de la sala)
static const uintptr_t G_EMLIST = 0x5410;    // GLOBAL_WK::Em_list_5410
static const int EMLIST_COUNT = 256;
static const int EMLIST_SIZE = 0x20;

struct Candidate
{
	uint8_t id;
	int liveCount;                 // cuantos enemigos asi hay vivos
	int listIndex;                 // de que entrada de la lista se copio
	uint8_t templ[EMLIST_SIZE];    // copia de esa entrada
};
static const int kCandMax = 16;

// ---- prueba de skin (hito 3i) ----
// F11 prueba crear el fantasma con el modelo de Leon (o de Ashley): se lee el numero de modelo (id) de sus
// personajes reales en memoria y se lo pone en la estructura EM_LIST que se copia de un enemigo vivo.
static int g_skinMode = 0;    // 0 = normal (copia del enemigo), 1 = id de Leon, 2 = id de Ashley
static int g_forceId = -1;    // -1 = no forzar
static uintptr_t g_realLeon = 0;  // el Leon verdadero (se guarda antes de crear el clon)
static int g_leonRestores = 0;    // veces que se le devolvio el puntero de Leon al verdadero

static bool ReadActorId(uintptr_t globalVar, int* id)
{
	uintptr_t actor = 0;
	uint8_t v = 0;
	if (!globalVar || !SafeRead(globalVar, &actor, 4) || actor < 0x10000)
		return false;
	if (!SafeRead(actor + EM_ID, &v, 1))
		return false;
	*id = v;
	return true;
}
static Candidate g_cands[kCandMax];
static int g_candCount = 0;
static int g_candIndex = 0;        // el elegido con F9
static uint8_t g_wantedId = 0x10;  // modelo preferido (re4coop.ini o ultimo elegido con F9)
static uint32_t g_candSig = 0;     // para anotar en el log solo cuando cambia la lista
static bool g_warnedNoCand = false;

// Mientras el juego esta dentro de una llamada arriesgada (crear el personaje o actualizar su matriz), el hilo
// del mod ve que g_riskStart != 0 y, si pasan mas de 7 segundos, lo anota en el log y (si esta activado)
// cierra el juego, para que no haya que reiniciar la PC.
static volatile DWORD g_riskStart = 0;
static volatile int g_riskCode = 0;   // 1 = EmSetEvent (crear el personaje), 2 = matUpdate (actualizar su matriz)
static volatile int g_riskId = 0;     // modelo involucrado
static bool g_killOnHang = true;
static int g_freezeMode = 3;   // 1 = sin movimiento, 2 = + sin animacion, 3 = + rutina fija, 4 = solo rutina fija con animacion (F10 cambia)

// Recorre la lista de personajes del juego y arma la lista de modelos disponibles (solo en el hilo del juego).
static void ScanCandidates()
{
	Candidate found[kCandMax];
	int n = 0;

	uintptr_t g = 0;
	uint32_t arr = 0, cnt = 0, size = 0;
	if (!g_pGvar || !g_emMgr || !SafeRead(g_pGvar, &g, 4) || g < 0x10000)
		return;
	if (!SafeRead(g_emMgr + 4, &arr, 4) || !SafeRead(g_emMgr + 8, &cnt, 4) || !SafeRead(g_emMgr + 0xC, &size, 4))
		return;
	if (arr == 0 || cnt == 0 || cnt > 4096 || size < 0x408 || size > 0x4000)
		return;

	for (uint32_t j = 0; j < cnt && n < kCandMax; j++)
	{
		uintptr_t em = (uintptr_t)arr + (uintptr_t)j * size;
		if (em == g_ghost.em)
			continue; // el propio fantasma no cuenta

		uint32_t flags = 0;
		uint8_t id = 0, li = 0;
		if (!SafeRead(em + EM_FLAGS, &flags, 4) || (flags & FLAG_VALID_MASK) == 0)
			continue;
		if (!SafeRead(em + EM_ID, &id, 1) || !SafeRead(em + EM_LISTIDX, &li, 1))
			continue;
		// 255 = el enemigo no viene de la lista de la sala (incluye a nuestros propios fantasmas).
		if (!IsAllowedModel(id) || li >= EMLIST_COUNT - 1)
			continue;

		uint8_t templ[EMLIST_SIZE];
		if (!SafeRead(g + G_EMLIST + (uintptr_t)li * EMLIST_SIZE, templ, EMLIST_SIZE))
			continue;
		if (templ[1] != id)
			continue; // la entrada de la lista no coincide con el enemigo: no es confiable

		int k = 0;
		while (k < n && found[k].id != id)
			k++;
		if (k < n)
		{
			found[k].liveCount++;
			continue;
		}
		found[n].id = id;
		found[n].liveCount = 1;
		found[n].listIndex = li;
		memcpy(found[n].templ, templ, EMLIST_SIZE);
		n++;
	}

	// Orden por id, para que F9 recorra siempre en el mismo orden.
	for (int a = 1; a < n; a++)
	{
		Candidate tmp = found[a];
		int b = a - 1;
		while (b >= 0 && found[b].id > tmp.id)
		{
			found[b + 1] = found[b];
			b--;
		}
		found[b + 1] = tmp;
	}

	uint32_t sig = 0;
	for (int i = 0; i < n; i++)
		sig = sig * 131u + (uint32_t)found[i].id + 1u;

	for (int i = 0; i < n; i++)
		g_cands[i] = found[i];
	g_candCount = n;

	// Mantener el modelo preferido si sigue disponible; si no, el primero.
	g_candIndex = 0;
	for (int i = 0; i < n; i++)
		if (g_cands[i].id == g_wantedId)
			g_candIndex = i;

	if (sig != g_candSig)
	{
		g_candSig = sig;
		char text[400];
		text[0] = '\0';
		size_t used = 0;
		for (int i = 0; i < n && used + 48 < sizeof(text); i++)
		{
			int w = snprintf(text + used, sizeof(text) - used, "%s0x%02X %s x%d",
				i ? ", " : "", g_cands[i].id, ModelName(g_cands[i].id), g_cands[i].liveCount);
			if (w < 0)
				break;
			used += (size_t)w;
		}
		if (n == 0)
			Log("Modelos disponibles ahora: ninguno (no hay enemigos compatibles vivos en esta sala)");
		else
			Log("Modelos disponibles ahora: %s", text);
	}
}

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
// Resumen de estado interno de un personaje (para el log): rutinas, animacion, vida y flags de estado.
// Vuelca n bytes de memoria como texto hexadecimal (para buscar en el log que campo cambia con la animacion).
static void HexDump(uintptr_t addr, int n, char* buf, size_t bufSize)
{
	buf[0] = '\0';
	size_t used = 0;
	for (int i = 0; i < n && used + 4 < bufSize; i++)
	{
		uint8_t b = 0;
		if (!SafeRead(addr + (uintptr_t)i, &b, 1))
		{
			snprintf(buf + used, bufSize - used, "?? ");
			used += 3;
			continue;
		}
		snprintf(buf + used, bufSize - used, "%02X ", (unsigned)b);
		used += 3;
	}
}

static void DescribeEm(uintptr_t em, char* buf, size_t bufSize)
{
	uint8_t r1 = 0, r2 = 0, r3 = 0;
	float frame = 0, frameMax = 0;
	uint16_t motState = 0;
	int16_t hp = 0;
	uint32_t st3cc = 0, f3d0 = 0, f3e8 = 0;
	SafeRead(em + 0xFD, &r1, 1);
	SafeRead(em + 0xFE, &r2, 1);
	SafeRead(em + 0xFF, &r3, 1);
	SafeRead(em + 0x1D8 + 0x24, &frame, 4);      // MOTION_INFO::Mot_frame_24
	SafeRead(em + 0x1D8 + 0x20, &frameMax, 4);   // MOTION_INFO::Mot_frame_max_20
	SafeRead(em + 0x1D8 + 0x42, &motState, 2);   // MOTION_INFO::Mot_state_42
	SafeRead(em + 0x324, &hp, 2);                // cEm::hp_324
	SafeRead(em + 0x3CC, &st3cc, 4);             // cEm::m_StatusFlag_3CC
	SafeRead(em + 0x3D0, &f3d0, 4);              // cEm::flag_3D0
	SafeRead(em + 0x3E8, &f3e8, 4);              // cEm::flags_3E8
	snprintf(buf, bufSize, "r1=%u r2=%u r3=%u anim=%.1f/%.1f estado_anim=%u hp=%d status=0x%08X f3D0=0x%08X f3E8=0x%08X",
		(unsigned)r1, (unsigned)r2, (unsigned)r3, frame, frameMax, (unsigned)motState, (int)hp,
		(unsigned)st3cc, (unsigned)f3d0, (unsigned)f3e8);
}

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

// Diagnostico (3o): anota las funciones virtuales del clon y de Leon para encontrar la que "piensa y mueve" al jugador.
static void DumpVtables(uintptr_t cloneEm)
{
	uintptr_t cloneVt = 0, leonVt = 0, leonEm = 0;
	SafeRead(cloneEm, &cloneVt, 4);
	if (g_plGlobal) SafeRead(g_plGlobal, &leonEm, 4);
	if (leonEm > 0x10000) SafeRead(leonEm, &leonVt, 4);
	HMODULE exe = GetModuleHandleA(nullptr);
	Log("VTABLE: base del exe=0x%08X clon em=0x%08X vtable=0x%08X | Leon em=0x%08X vtable=0x%08X (%s)",
		(unsigned)(uintptr_t)exe, (unsigned)cloneEm, (unsigned)cloneVt, (unsigned)leonEm, (unsigned)leonVt,
		cloneVt == leonVt ? "la misma" : "distintas");
	uintptr_t vt = cloneVt ? cloneVt : leonVt;
	if (!vt) return;
	char line[600];
	for (int row = 0; row < 8; row++)
	{
		line[0] = 0;
		size_t n = 0;
		for (int i = 0; i < 8; i++)
		{
			uint32_t fn = 0;
			SafeRead(vt + (row * 8 + i) * 4, &fn, 4);
			n += snprintf(line + n, sizeof(line) - n, "%08X ", (unsigned)fn);
		}
		Log("VTABLE[%02d..%02d]: %s", row * 8, row * 8 + 7, line);
	}
	// Los primeros 0x60 bytes del clon y de Leon (para ver que campos copia el clon de Leon).
	for (int who = 0; who < 2; who++)
	{
		uintptr_t e = who == 0 ? cloneEm : leonEm;
		if (e < 0x10000) continue;
		for (int row = 0; row < 3; row++)
		{
			line[0] = 0;
			size_t n = 0;
			for (int i = 0; i < 8; i++)
			{
				uint32_t v = 0;
				SafeRead(e + (row * 8 + i) * 4, &v, 4);
				n += snprintf(line + n, sizeof(line) - n, "%08X ", (unsigned)v);
			}
			Log("%s[+%02X]: %s", who == 0 ? "CLON " : "LEON ", row * 32, line);
		}
	}
}

// ---------------------------------------------------------------- 3p: tabla de funciones propia para el clon
// El clon de Leon comparte con Leon la misma tabla de funciones virtuales (22 entradas). Le damos al clon una COPIA de la tabla
// y, con F6, vamos anulando de a una funcion SOLO para el clon (la funcion anulada no hace nada y devuelve 0).
// Asi se descubre cual es la que lo hace copiar tus controles / pelear por la camara / deformar las manos.
static const int kVtSlots = 22;
static uint32_t g_vtCopy[kVtSlots];
static uint32_t g_slotOrig[kVtSlots];
static uint32_t g_slotReal[kVtSlots];
static int g_slotRet[kVtSlots];       // bytes de argumentos que limpia la funcion (-1 = no se pudo saber: no se prueba)
static bool g_vtReady = false;
static uint8_t* g_stubMem = nullptr;
static uint32_t g_clearMask = 0;      // 3s: bits que se le borran al clon en cada tick (F5)
static int g_testIdx = 0;
static bool g_autoFreezeMove = true;  // 3u: despues de inicializarse, al clon se le anula move() (la camara deja de pelear)
static int g_testSlot = -1;           // -1 = ninguna anulada, 0..21 = esa, 99 = todas las seguras (menos la 0)

// Lee el codigo de la funcion y busca como termina ("pop ...; ret" o "pop ...; ret N") para saber cuantos bytes de argumentos limpia.
static int AnalyzeRet(uint32_t fn, uint32_t* realFn)
{
	uint32_t a = fn;
	for (int hop = 0; hop < 4; hop++)
	{
		uint8_t b[5];
		if (!SafeRead(a, b, 5)) return -1;
		if (b[0] != 0xE9) break;
		int32_t rel = 0;
		memcpy(&rel, b + 1, 4);
		a = a + 5 + (uint32_t)rel;
	}
	*realFn = a;
	static uint8_t buf[0x600];
	size_t got = 0;
	while (got < sizeof(buf))
	{
		if (!SafeRead(a + got, buf + got, 64)) break;
		got += 64;
	}
	int val = -2;
	int cc = 0;
	for (size_t i = 1; i + 2 < got; i++)
	{
		if (buf[i] == 0xCC) { if (++cc >= 3 && i > 8) break; } else cc = 0;
		uint8_t p = buf[i - 1];
		bool pop = (p >= 0x58 && p <= 0x5F) || p == 0xC9;
		if (!pop) continue;
		int n = -2;
		if (buf[i] == 0xC3) n = 0;
		else if (buf[i] == 0xC2 && buf[i + 2] == 0) n = buf[i + 1];
		if (n == -2) continue;
		if (val == -2) val = n;
		else if (val != n) return -1;
	}
	return val == -2 ? -1 : val;
}

static void ApplyTestSlot()
{
	if (!g_vtReady || !g_stubMem) return;
	for (int i = 0; i < kVtSlots; i++)
	{
		bool disable = (g_testSlot == i) || (g_testSlot == 99 && i != 0);
		if (disable && g_slotRet[i] >= 0)
		{
			uint8_t* st = g_stubMem + i * 8;
			if (g_slotRet[i] == 0) { st[0] = 0x33; st[1] = 0xC0; st[2] = 0xC3; }
			else { st[0] = 0x33; st[1] = 0xC0; st[2] = 0xC2; st[3] = (uint8_t)g_slotRet[i]; st[4] = 0x00; }
			g_vtCopy[i] = (uint32_t)(uintptr_t)st;
		}
		else
			g_vtCopy[i] = g_slotOrig[i];
	}
}

static void SetupCloneVtable(uintptr_t em)
{
	uintptr_t vt = 0;
	if (!SafeRead(em, &vt, 4) || vt < 0x10000) return;
	if (!g_vtReady)
	{
		if (!g_stubMem)
			g_stubMem = (uint8_t*)VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!g_stubMem) { Log("VTABLE: no pude reservar memoria para las funciones de prueba"); return; }
		for (int i = 0; i < kVtSlots; i++)
		{
			g_slotOrig[i] = 0;
			SafeRead(vt + i * 4, &g_slotOrig[i], 4);
			uint32_t real = 0;
			g_slotRet[i] = g_slotOrig[i] ? AnalyzeRet(g_slotOrig[i], &real) : -1;
			g_slotReal[i] = real;
			// 3r: estas funciones se estudiaron a mano con el volcado del 3q: todas terminan con "ret" simple (0 bytes de argumentos).
			if (g_slotRet[i] < 0 && (i == 7 || i == 8 || i == 9 || i == 12 || i == 19 || i == 20 || i == 21))
				g_slotRet[i] = 0;
			Log("SLOT %02d: tabla=0x%08X codigo=0x%08X ret=%s%d", i, (unsigned)g_slotOrig[i], (unsigned)real,
				g_slotRet[i] < 0 ? "?" : "", g_slotRet[i]);
		}
		g_vtReady = true;
	}
	if (g_autoFreezeMove) { g_testSlot = -1; g_testIdx = 0; } // se anula move() recien cuando el clon termino de inicializarse
	ApplyTestSlot();
	uint32_t p = (uint32_t)(uintptr_t)g_vtCopy;
	if (SafeWrite(em, &p, 4))
		Log("VTABLE: el clon usa una copia de la tabla (funcion anulada ahora: %d)", g_testSlot);
}

// ---------------------------------------------------------------- 3w: animacion
// MOTION_INFO de un personaje: cEm + 0x1D8 (0xD0 bytes). Campos: +0 clip, +4 hermite, +8 historial (24 bytes), +0x20 frame max,
// +0x24 frame, +0x28/+0x2C frame anterior, +0x30 cantidad de huesos, +0x34 lista de huesos, +0x38 tipo de canal, +0x40 attr, +0x42 estado, +0x44 flag,
// +0xC0 velocidad.
static const uintptr_t EM_MOTION = 0x1D8;
static const uintptr_t EM_MOTTBL1 = 0x46C;
static const uintptr_t EM_MOTTBL2 = 0x470;
static const uintptr_t EM_SUBMOT = 0x474;   // cPlayer::m_SubMot_474 (segunda capa)
static bool g_motSubEval = true;           // F2 modo 3 = evaluar solo la capa principal
static bool g_motSub = true;                // segunda capa de animacion (siempre activa por ahora)

static uintptr_t g_motMoveFn = 0;    // MotionMoveCore(pEm, pInfo): evalua el clip y pone la pose de los huesos
static int g_motMoveRet = -1;        // bytes de argumentos que limpia la funcion (-1 = no se pudo saber)
static bool g_motEval = true;        // F2 (modo 2): llamar a la funcion que evalua la animacion
static bool g_motApply = true;       // F2 (modo 1): aplicar la animacion recibida al clon
static int g_motApplied = 0;

static uint32_t Fnv32(const uint8_t* p, int n)
{
	uint32_t h = 2166136261u;
	for (int i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
	return h;
}

static bool HashAt(uintptr_t a, uint32_t* out)
{
	uint8_t b[32];
	if (a < 0x10000 || !SafeRead(a, b, 32)) return false;
	*out = Fnv32(b, 32);
	return true;
}

// Lee el estado de animacion de un personaje y lo deja listo para mandar.
static void ReadMotionAt(uintptr_t em, uintptr_t infoOff, MotPart* m)
{
	memset(m, 0, sizeof(*m));
	m->tblIdx = -1;
	if (em < 0x10000) return;
	uint8_t mi[0xD0];
	if (!SafeRead(em + infoOff, mi, sizeof(mi))) return;
	uint32_t fcv, herm, jno, jkind;
	memcpy(&fcv, mi + 0, 4); memcpy(&herm, mi + 4, 4); memcpy(&jno, mi + 0x34, 4); memcpy(&jkind, mi + 0x38, 4);
	if (fcv < 0x10000) return;
	uint32_t t1 = 0, t2 = 0;
	SafeRead(em + EM_MOTTBL1, &t1, 4);
	SafeRead(em + EM_MOTTBL2, &t2, 4);
	if (t1 < 0x10000) return;
	// Referencia: el primer clip de la tabla (la pose quieta). Los clips estan todos en un mismo bloque que se carga igual en cada PC,
	// en cambio la tabla en si esta en otro lugar de la memoria en cada PC (por eso antes no coincidian).
	uint32_t anchor = 0;
	if (!SafeRead(t1, &anchor, 4) || anchor < 0x10000) return;
	m->dFcv = (int32_t)(fcv - anchor);
	m->dHerm = (int32_t)(herm - anchor);
	m->dJno = (int32_t)(jno - anchor);
	m->dJkind = (int32_t)(jkind - anchor);
	if (!HashAt(fcv, &m->hash)) return;
	memcpy(&m->frameMax, mi + 0x20, 4);
	memcpy(&m->frame, mi + 0x24, 4);
	memcpy(&m->speed, mi + 0xC0, 4);
	memcpy(&m->attr, mi + 0x40, 2);
	memcpy(&m->state, mi + 0x42, 2);
	memcpy(&m->flag, mi + 0x44, 4);
	m->jointNum = mi[0x30];
	// Buscar el clip en las tablas (para saber su indice).
	static uint32_t tbl[512];
	for (int sel = 0; sel < 2; sel++)
	{
		uint32_t t = sel == 0 ? t1 : t2;
		if (t < 0x10000) continue;
		if (!SafeRead(t, tbl, sizeof(tbl))) continue;
		bool hit = false;
		for (int i = 0; i < 512; i++)
			if (tbl[i] == fcv) { m->tblIdx = (int16_t)i; m->tblSel = (uint8_t)sel; hit = true; break; }
		if (hit) break;
	}
	{
		uint32_t pmb = 0;
		SafeRead(em + 0x2A8, &pmb, 4);
		m->pad[0] = (pmb == (uint32_t)(em + infoOff)) ? 1 : 0; // la capa esta "enchufada" como pMotionB del personaje
	}
	m->valid = 1;
}

static void ReadMotion(uintptr_t em, MotPart* m) { ReadMotionAt(em, EM_MOTION, m); }

// Busca MotionMoveCore (pEm, pInfo): el patron de re4_tweaks cae dentro de la funcion; se retrocede hasta su inicio.
static uintptr_t g_motSetFn = 0;   // MotionSet(pEm, pInfo, clip, seq, hokan, attr, frameInicial, flag): prepara un clip para usarlo (cdecl, 8 argumentos)

static void FindMotionMove()
{
	// MotionSet esta en 0x6611A0 del exe de Steam (estudiado desde bio4.exe); se busca por bytes porque la direccion cambia con ASLR.
	g_motSetFn = FindPattern("Preparar animacion (MotionSet)",
		"55 8B EC 83 EC 5C A1 ? ? ? ? 33 C5 89 45 FC 8B 45 08 53 56 8B 75 0C 33 C9 33 D2 F7 46 44 00 00 00 20");
	uintptr_t hit = FindPattern("MotionMoveCore (dentro)", "8A 45 88 A8 02 0F 84 ? ? ? ? D9 85 70 FF FF FF DD 05 ? ? ? ? D8 C1 D9 85 74 FF FF FF DE D9 DF E0 F6 C4 05 7B ? 80 7D 90 00 74 ? 80 7D 8F 00 75");
	if (!hit) return;
	static uint8_t buf[0x1800];
	uintptr_t start = hit - sizeof(buf) + 0x40;
	if (!SafeRead(start, buf, sizeof(buf))) { Log("MOTION: no pude leer el codigo antes de MotionMoveCore"); return; }
	size_t at = hit - start;
	uintptr_t entry = 0;
	for (size_t i = at; i > 8; i--)
		if (buf[i] == 0x55 && buf[i + 1] == 0x8B && buf[i + 2] == 0xEC && (buf[i - 1] == 0xCC || buf[i - 1] == 0xC3 || buf[i - 1] == 0x90))
		{ entry = start + i; break; }
	if (!entry) { Log("MOTION: no encontre el inicio de MotionMoveCore"); return; }
	uint32_t real = 0;
	g_motMoveRet = AnalyzeRet((uint32_t)entry, &real);
	g_motMoveFn = entry;
	Log("MOTION: MotionMoveCore empieza en 0x%08X (a %d bytes del patron), ret=%d", (unsigned)entry, (int)(hit - entry), g_motMoveRet);
	char hex[400];
	HexDump(entry, 48, hex, sizeof(hex));
	Log("MOTION: primeros bytes: %s", hex);

	// Quien la llama: se anotan las instrucciones previas a cada llamada (para ver cuantos argumentos se empujan).
	uint8_t* base = (uint8_t*)GetModuleHandleA(nullptr);
	auto dos = (PIMAGE_DOS_HEADER)base;
	auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
	auto sec = IMAGE_FIRST_SECTION(nt);
	int found = 0;
	for (unsigned k = 0; k < nt->FileHeader.NumberOfSections && found < 8; k++, sec++)
	{
		if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
		uint8_t* st = base + sec->VirtualAddress;
		size_t sz = sec->Misc.VirtualSize;
		for (size_t o = 24; o + 16 < sz && found < 8; o++)
		{
			if (st[o] != 0xE8) continue;
			int32_t rel; memcpy(&rel, st + o + 1, 4);
			if ((uintptr_t)(st + o + 5) + rel != entry) continue;
			found++;
			char h1[200], h2[100];
			HexDump((uintptr_t)(st + o - 24), 24, h1, sizeof(h1));
			HexDump((uintptr_t)(st + o), 12, h2, sizeof(h2));
			Log("MOTION: llamada #%d en 0x%08X | antes: %s | desde la llamada: %s", found, (unsigned)(uintptr_t)(st + o), h1, h2);
		}
	}
	if (!found) Log("MOTION: no se encontraron llamadas directas a MotionMoveCore");
}

// Llama a MotionMoveCore(em, info) sin importar si la funcion limpia la pila o no (se restaura esp a mano).
static DWORD g_motExCode = 0;
static uintptr_t g_motExAddr = 0;
static uintptr_t g_motExInfo0 = 0, g_motExInfo1 = 0;
static DWORD g_motExRegs[7] = { 0, 0, 0, 0, 0, 0, 0 };
static int MotFilter(EXCEPTION_POINTERS* ep)
{
	if (ep && ep->ExceptionRecord)
	{
		g_motExCode = ep->ExceptionRecord->ExceptionCode;
		g_motExAddr = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;
		g_motExInfo0 = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[0];
		g_motExInfo1 = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
	}
	if (ep && ep->ContextRecord)
	{
		g_motExRegs[0] = ep->ContextRecord->Eax; g_motExRegs[1] = ep->ContextRecord->Ebx; g_motExRegs[2] = ep->ContextRecord->Ecx;
		g_motExRegs[3] = ep->ContextRecord->Edx; g_motExRegs[4] = ep->ContextRecord->Esi; g_motExRegs[5] = ep->ContextRecord->Edi;
		g_motExRegs[6] = ep->ContextRecord->Ebp;
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

static bool CallMotionMove(uintptr_t em, uintptr_t info)
{
	if (!g_motMoveFn) return false;
	__try
	{
#if defined(_MSC_VER) && defined(_M_IX86)
		DWORD fnV = (DWORD)g_motMoveFn, emV = (DWORD)em, infoV = (DWORD)info;
		__asm {
			mov esi, esp
			push infoV
			push emV
			call fnV
			mov esp, esi
		}
#endif
		return true;
	}
	__except (MotFilter(GetExceptionInformation()))
	{
		return false;
	}
}

// Llama a MotionSet (cdecl, 8 argumentos). Es la funcion que usa el propio juego para empezar un clip: deja bien los punteros,
// "arregla" (suma la base a) los datos del clip la primera vez que se usa en esta PC, y prepara el mezclado con la pose anterior.
static bool CallMotionSet(uintptr_t em, uintptr_t info, uint32_t fcv, uint32_t hokan, uint32_t attr, float frame)
{
	if (!g_motSetFn) return false;
#if defined(_MSC_VER) && defined(_M_IX86)
	DWORD fnV = (DWORD)g_motSetFn, emV = (DWORD)em, infoV = (DWORD)info, fcvV = (DWORD)fcv, hokanV = (DWORD)hokan, attrV = (DWORD)attr;
	DWORD frameBits = 0;
	memcpy(&frameBits, &frame, 4);
	__try
	{
		__asm
		{
			mov esi, esp
			push 0
			push frameBits
			push attrV
			push hokanV
			push 0
			push fcvV
			push infoV
			push emV
			call fnV
			mov esp, esi
		}
		return true;
	}
	__except (MotFilter(GetExceptionInformation()))
	{
		return false;
	}
#else
	(void)em; (void)info; (void)fcv; (void)hokan; (void)attr; (void)frame;
	return false;
#endif
}

// Lado que recibe: escribe la animacion del otro jugador en el clon y evalua la pose. Dos capas: 0 = principal, 1 = secundaria.
struct MotLayer
{
	int32_t key[4];
	bool keyValid;
	bool clipOk;
	uint32_t fcv;
	float frame;
	uint32_t lastStamp;
	int clipChanges, hashFail, evalOk, evalFail, skipped, setOk, setFail;
};
static MotLayer g_motL[2];
static int g_motViaIdx = 0, g_motNoTbl = 0;
static bool g_motTablesLogged = false;
static uint32_t g_motBad[2][24];
static int g_motBadN[2] = { 0, 0 };

static bool IsSaneFloat(float f, float lo, float hi) { return f == f && f >= lo && f <= hi; }

static bool MotIsBad(int layer, uint32_t fcv)
{
	for (int i = 0; i < g_motBadN[layer]; i++) if (g_motBad[layer][i] == fcv) return true;
	return false;
}

static void MotionApplyLayer(int layer, uintptr_t em, uintptr_t infoOff, const MotPart& p, uint32_t stamp, uint32_t anchor, float dt)
{
	MotLayer& L = g_motL[layer];
	if (!p.valid) return;
	if (!IsSaneFloat(p.frameMax, 1.0f, 5000.0f) || !IsSaneFloat(p.frame, -1.0f, 5000.0f)) return;
	float speed = IsSaneFloat(p.speed, 0.0f, 4.0f) ? p.speed : 1.0f;
	uintptr_t info = em + infoOff;

	int32_t key[4] = { p.dFcv, p.dHerm, p.dJno, p.dJkind };
	bool newClip = !L.keyValid || memcmp(key, L.key, sizeof(key)) != 0;
	if (newClip)
	{
		memcpy(L.key, key, sizeof(key));
		L.keyValid = true;
		L.clipChanges++;
		L.clipOk = false;
		uint32_t cand[2] = { anchor + (uint32_t)p.dFcv, 0 };
		if (layer == 0 && p.tblIdx >= 0)
		{
			uint32_t tb = 0, e = 0;
			if (SafeRead(em + (p.tblSel ? EM_MOTTBL2 : EM_MOTTBL1), &tb, 4) && tb > 0x10000 && SafeRead(tb + (uintptr_t)p.tblIdx * 4, &e, 4))
				cand[1] = e;
		}
		for (int c = 0; c < 2 && !L.clipOk; c++)
		{
			uint32_t h = 0;
			if (!HashAt(cand[c], &h) || h != p.hash) continue;
			L.fcv = cand[c];
			L.clipOk = true;
			if (c == 1) g_motViaIdx++;
		}
		if (!L.clipOk)
		{
			L.hashFail++;
			if (L.hashFail <= 8)
				Log("MOTION[%d]: no pude encontrar el clip del otro jugador (dFcv=%d idx=%d hash=%08X max=%.0f)", layer, (int)p.dFcv, (int)p.tblIdx,
					(unsigned)p.hash, p.frameMax);
		}
		else if (g_motSetFn && CallMotionSet(em, info, L.fcv, 3, (uint32_t)(p.attr & 0xFF), p.frame))
		{
			L.setOk++;
			L.frame = p.frame;
			L.lastStamp = stamp;
			if (L.clipChanges <= 6)
				Log("MOTION[%d]: clip nuevo preparado con MotionSet (fcv=0x%08X max=%.0f juntas=%d attr=0x%04X)", layer, (unsigned)L.fcv, p.frameMax,
					(int)p.jointNum, (unsigned)p.attr);
		}
		else
		{
			if (g_motSetFn)
			{
				L.setFail++;
				if (L.setFail <= 4)
					Log("MOTION[%d]: fallo MotionSet (codigo 0x%08X en 0x%08X) clip fcv=0x%08X; se usa el metodo manual", layer, (unsigned)g_motExCode,
						(unsigned)g_motExAddr, (unsigned)L.fcv);
			}
			uint32_t herm = L.fcv + (uint32_t)(p.dHerm - p.dFcv);
			uint32_t jno = L.fcv + (uint32_t)(p.dJno - p.dFcv);
			uint32_t jk = L.fcv + (uint32_t)(p.dJkind - p.dFcv);
			uint8_t zero[24];
			memset(zero, 0, sizeof(zero));
			SafeWrite(info + 0x00, &L.fcv, 4);
			SafeWrite(info + 0x04, &herm, 4);
			SafeWrite(info + 0x08, zero, 24);
			SafeWrite(info + 0x20, &p.frameMax, 4);
			SafeWrite(info + 0x30, &p.jointNum, 1);
			SafeWrite(info + 0x34, &jno, 4);
			SafeWrite(info + 0x38, &jk, 4);
			{
				// Lo que hace MotionSet con los datos del clip: si todavia son distancias (menores que la direccion del clip), se les suma la base.
				uint32_t first = 0;
				if (SafeRead(herm, &first, 4) && first < L.fcv)
					for (int i = 0; i < (int)p.jointNum; i++)
					{
						uint32_t v = 0;
						if (!SafeRead(herm + i * 4, &v, 4)) break;
						v += L.fcv;
						SafeWrite(herm + i * 4, &v, 4);
					}
			}
			L.frame = p.frame;
			L.lastStamp = stamp;
			if (L.clipChanges <= 6)
				Log("MOTION[%d]: clip nuevo aplicado (fcv=0x%08X max=%.0f juntas=%d attr=0x%04X estado=0x%04X flag=0x%08X)", layer, (unsigned)L.fcv, p.frameMax,
					(int)p.jointNum, (unsigned)p.attr, (unsigned)p.state, (unsigned)p.flag);
		}
	}
	if (!L.clipOk) return;

	if (stamp != L.lastStamp)
	{
		L.lastStamp = stamp;
		float diff = p.frame - L.frame;
		if (fabsf(diff) > 6.0f) L.frame = p.frame; else L.frame += diff * 0.5f;
	}
	else
		L.frame += dt * 30.0f * speed;
	if (L.frame >= p.frameMax) L.frame = p.frameMax - 0.01f;
	if (L.frame < 0.0f) L.frame = 0.0f;

	float oldFrame = 0.0f;
	SafeRead(info + 0x24, &oldFrame, 4);
	SafeWrite(info + 0x20, &p.frameMax, 4);
	SafeWrite(info + 0x24, &L.frame, 4);
	SafeWrite(info + 0x28, &L.frame, 4);
	SafeWrite(info + 0x2C, &oldFrame, 4);
	SafeWrite(info + 0x40, &p.attr, 2);
	SafeWrite(info + 0x42, &p.state, 2);
	SafeWrite(info + 0x44, &p.flag, 4);
	g_motApplied++;

	if (g_motEval && g_motMoveFn && (layer == 0 || g_motSubEval))
	{
		if (MotIsBad(layer, L.fcv)) { L.skipped++; return; }
		g_riskId = g_ghost.id;
		g_riskCode = 2;
		g_riskStart = GetTickCount();
		bool ok = CallMotionMove(em, info);
		g_riskStart = 0;
		if (ok) L.evalOk++;
		else
		{
			L.evalFail++;
			if (g_motBadN[layer] < 24) g_motBad[layer][g_motBadN[layer]++] = L.fcv; // ese clip no se vuelve a evaluar
			if (L.evalFail <= 4)
			{
				char before[200], after[100];
				HexDump(g_motExAddr - 24, 24, before, sizeof(before));
				HexDump(g_motExAddr, 12, after, sizeof(after));
				Log("MOTION[%d]: FALLO MotionMoveCore codigo 0x%08X en 0x%08X (%s direccion 0x%08X) clip fcv=0x%08X max=%.0f juntas=%d attr=0x%04X",
					layer, (unsigned)g_motExCode, (unsigned)g_motExAddr, g_motExInfo0 == 1 ? "escribiendo" : "leyendo", (unsigned)g_motExInfo1,
					(unsigned)L.fcv, p.frameMax, (int)p.jointNum, (unsigned)p.attr);
				Log("MOTION[%d]: regs eax=%08X ebx=%08X ecx=%08X edx=%08X esi=%08X edi=%08X ebp=%08X | em=0x%08X info=0x%08X", layer,
					(unsigned)g_motExRegs[0], (unsigned)g_motExRegs[1], (unsigned)g_motExRegs[2], (unsigned)g_motExRegs[3], (unsigned)g_motExRegs[4],
					(unsigned)g_motExRegs[5], (unsigned)g_motExRegs[6], (unsigned)em, (unsigned)info);
				Log("MOTION[%d]: codigo antes: %s| desde la falla: %s", layer, before, after);
			}
		}
	}
}

static void MotionApply(const RemoteSnap& snap, float dt)
{
	if (!g_motApply || !g_ghost.em || !snap.mot.valid) return;
	uintptr_t em = g_ghost.em;
	uint32_t anchor = 0;
	{
		uint32_t t = 0;
		if (g_realLeon > 0x10000 && SafeRead(g_realLeon + EM_MOTTBL1, &t, 4) && t > 0x10000) SafeRead(t, &anchor, 4);
		if (anchor < 0x10000 && SafeRead(em + EM_MOTTBL1, &t, 4) && t > 0x10000) SafeRead(t, &anchor, 4);
		if (anchor < 0x10000) { g_motNoTbl++; return; }
	}
	MotionApplyLayer(0, em, EM_MOTION, snap.mot, snap.motStamp, anchor, dt);
	if (g_motSub)
	{
		MotionApplyLayer(1, em, EM_SUBMOT, snap.sub, snap.motStamp, anchor, dt);
		// Igual que en el otro PC: la segunda capa esta enchufada (pMotionB) o no. MotionSet lo borra, por eso se vuelve a poner.
		uint32_t pmb = (snap.sub.valid && snap.sub.pad[0] && g_motL[1].clipOk) ? (uint32_t)(em + EM_SUBMOT) : 0;
		SafeWrite(em + 0x2A8, &pmb, 4);
	}
}

// 3z2: posicion de cada parte del cuerpo (mundo relativa a la raiz | posicion local | escala) para ver si faltan piernas, etc.
static void PartsLog(const char* tag, uintptr_t em)
{
	if (em < 0x10000) return;
	float root[3] = { 0, 0, 0 };
	SafeRead(em + 0x94, root, 12);
	uint32_t p = 0;
	SafeRead(em + 0xF4, &p, 4);
	char line[500];
	line[0] = 0;
	size_t used = 0;
	int n = 0, idx = 0;
	while (p > 0x10000 && idx < 40)
	{
		float w[3] = { 0, 0, 0 }, loc[3] = { 0, 0, 0 }, sc[3] = { 0, 0, 0 };
		SafeRead(p + 0x18, &w[0], 4);
		SafeRead(p + 0x28, &w[1], 4);
		SafeRead(p + 0x38, &w[2], 4);
		SafeRead(p + 0x94, loc, 12);
		SafeRead(p + 0xAC, sc, 12);
		used += snprintf(line + used, sizeof(line) - used, "%d:(%.0f,%.0f,%.0f|%.0f,%.0f,%.0f|%.2f) ", idx, w[0] - root[0], w[1] - root[1], w[2] - root[2],
			loc[0], loc[1], loc[2], sc[0]);
		if (++n == 5) { Log("%s %s", tag, line); line[0] = 0; used = 0; n = 0; }
		uint32_t nx = 0;
		if (!SafeRead(p + 0xF4, &nx, 4)) break;
		p = nx;
		idx++;
	}
	if (n) Log("%s %s", tag, line);
	Log("%s total de partes: %d", tag, idx);
}

// Una linea por segundo (y un volcado de las tablas la primera vez) para entender como se identifican los clips.
static void MotionLog()
{
	uintptr_t le = 0;
	if (g_plGlobal) SafeRead(g_plGlobal, &le, 4);
	if (le > 0x10000)
	{
		MotPart q;
		ReadMotion(le, &q);
		uint32_t t0 = 0, t1 = 0;
		SafeRead(le + EM_MOTTBL1, &t0, 4);
		SafeRead(le + EM_MOTTBL2, &t1, 4);
		if (!g_motTablesLogged && t0 > 0x10000)
		{
			g_motTablesLogged = true;
			uintptr_t ce = g_ghost.em;
			uint32_t c0 = 0, c1 = 0;
			if (ce) { SafeRead(ce + EM_MOTTBL1, &c0, 4); SafeRead(ce + EM_MOTTBL2, &c1, 4); }
			Log("MOTION-TABLAS: Leon 46C=0x%08X 470=0x%08X | clon 46C=0x%08X 470=0x%08X", (unsigned)t0, (unsigned)t1, (unsigned)c0, (unsigned)c1);
			for (int sel = 0; sel < 2; sel++)
			{
				uint32_t tb = sel ? t1 : t0;
				if (tb < 0x10000) continue;
				for (int row = 0; row < 6; row++)
				{
					uint32_t e[8];
					if (!SafeRead(tb + row * 32, e, sizeof(e))) break;
					Log("MOTION-TABLA%d[%02d..%02d]: %08X %08X %08X %08X %08X %08X %08X %08X", sel, row * 8, row * 8 + 7,
						(unsigned)e[0], (unsigned)e[1], (unsigned)e[2], (unsigned)e[3], (unsigned)e[4], (unsigned)e[5], (unsigned)e[6], (unsigned)e[7]);
				}
			}
		}
		Log("MOTION-LEON: valido=%d dFcv=%d dHerm=%d dJno=%d dJkind=%d idx=%d/%d hash=%08X frame=%.1f/%.0f vel=%.2f attr=0x%04X estado=0x%04X flag=0x%08X juntas=%d",
			(int)q.valid, (int)q.dFcv, (int)q.dHerm, (int)q.dJno, (int)q.dJkind, (int)q.tblIdx, (int)q.tblSel, (unsigned)q.hash,
			q.frame, q.frameMax, q.speed, (unsigned)q.attr, (unsigned)q.state, (unsigned)q.flag, (int)q.jointNum);
	}
	RemoteSnap rs = GetRemoteSnap();
	for (int ly = 0; ly < 2; ly++)
	{
		const MotLayer& L = g_motL[ly];
		Log("MOTION-CLON[%d]: aplicar=%d evaluar=%d recibido=%d clipOk=%d aplicado=%d clipsNuevos=%d fallaHash=%d porIndice=%d evalOk=%d evalFalla=%d omitidos=%d malos=%d setOk=%d setFalla=%d frame=%.1f",
			ly, (int)g_motApply, (int)g_motEval, (int)(ly ? rs.sub.valid : rs.mot.valid), (int)L.clipOk, g_motApplied, L.clipChanges, L.hashFail, g_motViaIdx,
			L.evalOk, L.evalFail, L.skipped, g_motBadN[ly], L.setOk, L.setFail, L.frame);
	}
	if (le > 0x10000)
	{
		MotPart q2;
		ReadMotionAt(le, EM_SUBMOT, &q2);
		uint32_t pb[3] = { 0, 0, 0 }, cb[3] = { 0, 0, 0 };
		SafeRead(le + 0x2A8, &pb[0], 4); SafeRead(le + 0x2AC, &pb[1], 4); SafeRead(le + 0x2B0, &pb[2], 4);
		if (g_ghost.em) { SafeRead(g_ghost.em + 0x2A8, &cb[0], 4); SafeRead(g_ghost.em + 0x2AC, &cb[1], 4); SafeRead(g_ghost.em + 0x2B0, &cb[2], 4); }
		Log("MOTION-CAPA2-LEON: valido=%d dFcv=%d hash=%08X frame=%.1f/%.0f attr=0x%04X estado=0x%04X flag=0x%08X juntas=%d | pMotionB=0x%08X (Leon+0x474=0x%08X) xflip=0x%08X dbljnt=0x%08X | clon pMotionB=0x%08X (clon+0x474=0x%08X)",
			(int)q2.valid, (int)q2.dFcv, (unsigned)q2.hash, q2.frame, q2.frameMax, (unsigned)q2.attr, (unsigned)q2.state, (unsigned)q2.flag, (int)q2.jointNum,
			(unsigned)pb[0], (unsigned)(le + EM_SUBMOT), (unsigned)pb[1], (unsigned)pb[2], (unsigned)cb[0], (unsigned)(g_ghost.em + EM_SUBMOT));
	}
	{
		static int s_partsCount = 0;
		if (g_ghost.em && (s_partsCount++ % 6) == 2)
		{
			if (le > 0x10000) PartsLog("PARTES-LEON", le);
			PartsLog("PARTES-CLON", g_ghost.em);
		}
	}
	if (g_ghost.em)
	{
		char hex[260];
		HexDump(g_ghost.em + EM_MOTION, 0x48, hex, sizeof(hex));
		Log("MOTION-CLON-INFO: %s", hex);
	}
}

// ---------------------------------------------------------------- 3t: camara
// La camara del juego (CameraControl) guarda a que modelo esta "pegada": m_p_model_10[3] (+0x10..+0x18) y m_p_attach_model_old_1C (+0x1C).
// Hipotesis: al crearse, el clon (que es un jugador completo) pega la camara a si mismo. Aca la devolvemos a Leon.
static uintptr_t g_camCtrl = 0;
static uintptr_t g_camSnap[4] = { 0, 0, 0, 0 };
static int g_camRestores = 0;
static bool g_cloneMotion = true;   // 3t: el clon NO lleva la bandera "sin animacion" (F3 la alterna)

static void CamLog(const char* when)
{
	if (!g_camCtrl) return;
	uintptr_t m[4] = { 0, 0, 0, 0 };
	for (int i = 0; i < 3; i++) SafeRead(g_camCtrl + 0x10 + 4 * i, &m[i], 4);
	SafeRead(g_camCtrl + 0x1C, &m[3], 4);
	uint8_t at[3] = { 0, 0, 0 };
	SafeRead(g_camCtrl + 0x00, &at[0], 1);
	SafeRead(g_camCtrl + 0x01, &at[1], 1);
	SafeRead(g_camCtrl + 0x02, &at[2], 1);
	uint32_t bf = 0, sf = 0, st = 0;
	SafeRead(g_camCtrl + 0x28, &bf, 4);
	SafeRead(g_camCtrl + 0x2C, &sf, 4);
	SafeRead(g_camCtrl + 0x30, &st, 4);
	Log("CAMARA (%s): modelo[0]=0x%08X modelo[1]=0x%08X modelo[2]=0x%08X anterior=0x%08X adj=%u/%u/%u flag28=0x%X sys2C=0x%X est30=0x%X",
		when, (unsigned)m[0], (unsigned)m[1], (unsigned)m[2], (unsigned)m[3], at[0], at[1], at[2], (unsigned)bf, (unsigned)sf, (unsigned)st);
}

// 3v: a quien "mira" la camara: posicion del jugador que usa la camara (matriz del modo sobre el hombro) y objetivo de la camara,
// comparados con la posicion de Leon y del clon.
static void CamDiag()
{
	if (!g_camCtrl || !g_ghost.em) return;
	float pl[3] = { 0, 0, 0 }, camPos[3] = { 0, 0, 0 }, camTgt[3] = { 0, 0, 0 }, leon[3] = { 0, 0, 0 }, clon[3] = { 0, 0, 0 };
	SafeRead(g_camCtrl + 0x3F0 + 0x0C, &pl[0], 4);
	SafeRead(g_camCtrl + 0x3F0 + 0x1C, &pl[1], 4);
	SafeRead(g_camCtrl + 0x3F0 + 0x2C, &pl[2], 4);
	SafeRead(g_camCtrl + 0x104, camPos, 12);
	SafeRead(g_camCtrl + 0x110, camTgt, 12);
	uintptr_t le = 0;
	if (g_plGlobal) SafeRead(g_plGlobal, &le, 4);
	if (le > 0x10000) SafeRead(le + 0x94, leon, 12);
	SafeRead(g_ghost.em + 0x94, clon, 12);
	auto d = [](const float* a, const float* b) { float x = a[0] - b[0], y = a[1] - b[1], z = a[2] - b[2]; return sqrtf(x * x + y * y + z * z); };
	Log("CAMARA-DIAG: jugador_de_camara=(%.0f,%.0f,%.0f) a_Leon=%.0f a_clon=%.0f | objetivo=(%.0f,%.0f,%.0f) a_Leon=%.0f a_clon=%.0f | camara_a_Leon=%.0f",
		pl[0], pl[1], pl[2], d(pl, leon), d(pl, clon), camTgt[0], camTgt[1], camTgt[2], d(camTgt, leon), d(camTgt, clon), d(camPos, leon));
}

static void CamSnapshot()
{
	if (!g_camCtrl) return;
	for (int i = 0; i < 3; i++) SafeRead(g_camCtrl + 0x10 + 4 * i, &g_camSnap[i], 4);
	SafeRead(g_camCtrl + 0x1C, &g_camSnap[3], 4);
}

// Si la camara quedo pegada al clon, se la devuelve a lo que tenia antes (o a Leon).
static int CamRestore(uintptr_t cloneEm)
{
	if (!g_camCtrl || !cloneEm) return 0;
	int fixed = 0;
	for (int i = 0; i < 4; i++)
	{
		uintptr_t a = g_camCtrl + (i < 3 ? 0x10 + 4 * i : 0x1C);
		uintptr_t cur = 0;
		if (!SafeRead(a, &cur, 4) || cur != cloneEm) continue;
		uintptr_t back = g_camSnap[i];
		if (back == cloneEm || (i == 0 && back == 0)) back = g_realLeon;
		SafeWrite(a, &back, 4);
		fixed++;
	}
	if (fixed)
	{
		g_camRestores += fixed;
		if (g_camRestores <= 8 || g_camRestores % 600 == 0)
			Log("CAMARA: estaba pegada al clon, se devolvio a Leon (veces: %d)", g_camRestores);
	}
	return fixed;
}

static void GhostSpawn(const RemoteSnap& snap, uint16_t room)
{
	// Elegimos el modelo entre los que ya estan cargados en la sala (se vuelve a mirar justo ahora).
	ScanCandidates();
	// Plantilla propia para el clon de Leon: no depende de que haya un enemigo vivo (copiada de un registro real de la sala 0x0100).
	static const uint8_t kLeonTempl[EMLIST_SIZE] = {
		0x01, 0x12, 0x04, 0x00, 0x3C, 0x00, 0x00, 0x80, 0xE8, 0x03, 0xFF, 0x01, 0xCE, 0xDE, 0x03, 0x00,
		0xF8, 0xFB, 0x00, 0x00, 0x1F, 0xC0, 0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00 };
	Candidate own;
	memset(&own, 0, sizeof(own));
	const Candidate* cp = nullptr;
	if (g_forceId >= 0 && g_candCount == 0)
	{
		own.id = (uint8_t)g_forceId;
		own.liveCount = 0;
		own.listIndex = -1;
		memcpy(own.templ, kLeonTempl, EMLIST_SIZE);
		cp = &own;
		Log("PRUEBA DE SKIN: no hay enemigos vivos, se usa la plantilla propia");
	}
	else if (g_candCount == 0)
	{
		g_holdUntil = GetTickCount() + 500;
		return; // no es un fallo: todavia no hay un enemigo del que copiar el modelo
	}
	else
	{
		if (g_candIndex >= g_candCount)
			g_candIndex = 0;
		cp = &g_cands[g_candIndex];
	}
	const Candidate& c = *cp;
	uint8_t id = c.id;
	Log("Creando fantasma: modelo 0x%02X (%s), copiado de la entrada %d de la lista de la sala (hay %d vivos asi), sala 0x%04X ...",
		id, ModelName(id), c.listIndex, c.liveCount, room);

	// Armamos la estructura EM_LIST copiando la entrada real de un enemigo de ese modelo
	// y cambiando solo lo necesario.
	memcpy(g_emList, c.templ, sizeof(g_emList));
	if (g_forceId >= 0)
	{
		g_emList[1] = (uint8_t)g_forceId;
		id = (uint8_t)g_forceId;
		Log("PRUEBA DE SKIN: se pide el modelo 0x%02X (en vez del 0x%02X del enemigo copiado)", id, c.id);
	}
	g_emList[0] = 0x01;            // be_flag_0: vivo, sin otras marcas
	g_emList[0x0A] = 0xFF;         // emset_no_A: no pertenece a la lista de la sala
	int16_t hp = 1000;
	memcpy(g_emList + 0x08, &hp, 2);
	memset(g_emList + 0x1C, 0, 4); // campos de extension de re4_tweaks: sin escala ni velocidad especial
	// Posicion inicial: el juego guarda las posiciones del archivo ESL en shorts (aprox. mundo / 10).
	// Es solo el punto de partida: despues la fijamos nosotros cada frame.
	// (room_18 se deja como esta: viene de un enemigo vivo de esta misma sala.)
	PutShort(g_emList, 0x0C, (int)(snap.pos[0] / 10.0f));
	PutShort(g_emList, 0x0E, (int)(snap.pos[1] / 10.0f));
	PutShort(g_emList, 0x10, (int)(snap.pos[2] / 10.0f));

	// Queda anotado exactamente lo que se le pasa al juego: si se cuelga, sirve para ver por que.
	char hex[EMLIST_SIZE * 3 + 1];
	hex[0] = '\0';
	for (int i = 0; i < EMLIST_SIZE; i++)
		snprintf(hex + i * 3, 4, "%02X ", g_emList[i]);
	Log("EM_LIST que se envia al juego: %s", hex);

	g_realLeon = 0;
	if (g_forceId >= 0)
	{
		uintptr_t cur = 0;
		if (g_plGlobal && SafeRead(g_plGlobal, &cur, 4) && cur > 0x10000)
		{
			g_realLeon = cur;
			g_leonRestores = 0;
			Log("PRUEBA DE SKIN: Leon verdadero guardado en 0x%08X", (unsigned)g_realLeon);
		}
		else
		{
			Log("PRUEBA DE SKIN: no pude leer a Leon, se cancela la prueba");
			g_forceId = -1; g_skinMode = 0;
			return;
		}
	}
	uintptr_t em = 0;
	if (g_forceId >= 0) { CamSnapshot(); CamLog("antes de crear el clon"); }
	g_riskId = id;
	g_riskCode = 1;
	g_riskStart = GetTickCount();
	bool spawnOk = SafeSpawn(g_emList, &em);
	g_riskStart = 0;
	if (!spawnOk)
	{
		Log("ERROR: el juego dio una excepcion al crear el modelo 0x%02X", id);
		if (g_forceId >= 0) { Log("Se vuelve al modelo normal."); g_forceId = -1; g_skinMode = 0; }
		g_spawnFails++;
		g_holdUntil = GetTickCount() + 2000;
		return;
	}
	Log("EmSetEvent devolvio 0x%08X", (unsigned)em);
	if (g_realLeon && em)
	{
		uintptr_t cur = 0;
		if (SafeRead(g_plGlobal, &cur, 4) && cur != g_realLeon)
		{
			SafeWrite(g_plGlobal, &g_realLeon, 4);
			Log("PRUEBA DE SKIN: el juego habia cambiado el puntero de Leon a 0x%08X; se devolvio al verdadero 0x%08X",
				(unsigned)cur, (unsigned)g_realLeon);
		}
	}

	if (g_forceId >= 0 && em)
	{
		CamLog("justo despues de crear el clon");
		CamRestore(em);
	}

	// Comprobamos que el resultado sea un personaje valido de la lista del juego.
	memset(&g_ghost, 0, sizeof(g_ghost));
	g_ghost.em = em;
	g_ghost.id = id;
	g_ghost.isClone = (g_forceId >= 0);
	uint32_t guid = 0;
	uint8_t realId = 0;
	if (em == 0 || !SafeRead(em + EM_GUID, &guid, 4) || !SafeRead(em + EM_ID, &realId, 1))
	{
		Log("ERROR: el juego no devolvio un personaje valido para el modelo 0x%02X", id);
		if (g_forceId >= 0) { Log("Se vuelve al modelo normal."); g_forceId = -1; g_skinMode = 0; }
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

	if (g_ghost.isClone)
	{
		DumpVtables(em);
		SetupCloneVtable(em);
	}

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

	// 3u: pasados unos frames (el clon ya se inicializo), se le anula move(): asi no copia tus controles ni toca la camara.
	if (g_ghost.isClone && g_autoFreezeMove && g_ghost.frames == 40 && g_vtReady && g_testSlot != 4)
	{
		g_testSlot = 4;
		g_testIdx = 1;
		ApplyTestSlot();
		Log("CLON: se anulo move() (funcion 4) para que no pelee por la camara ni copie tus controles");
	}

	// Cuando el personaje termino de inicializarse, le quitamos el movimiento propio (IA/animacion).
	if (!g_ghost.frozen)
	{
		uint8_t rno0 = 0;
		uint32_t flags = 0;
		if (SafeRead(g_ghost.em + EM_RNO0, &rno0, 1) && SafeRead(g_ghost.em + EM_FLAGS, &flags, 4))
		{
			if (rno0 != 0 || (g_ghost.isClone && g_ghost.frames >= 2))
			{
				flags &= ~FLAG_MOVE;
				SafeWrite(g_ghost.em + EM_FLAGS, &flags, 4);
				g_ghost.frozen = true;
				Log("Fantasma congelado (inicializado tras %d frames, r_no_0=%u)", g_ghost.frames, (unsigned)rno0);
			}
			else if (g_ghost.frames > 60)
			{
				g_ghost.frozen = true;
				g_ghost.reFrozen = -1; // no se le quita el movimiento
				Log("AVISO: el fantasma no termino de inicializarse en 60 frames; se deja con su movimiento propio");
			}
		}
	}
	else if (g_ghost.reFrozen >= 0)
	{
		// Modo 1: sin movimiento propio. Modo 2: ademas sin animacion (para que no pueda ejecutar ataques).
		// Modo 3: ademas se mantiene fija su rutina interna (r_no_1/2/3) en la que tenia tranquilo.
		uint32_t flags = 0;
		if (SafeRead(g_ghost.em + EM_FLAGS, &flags, 4))
		{
			uint32_t want = flags & ~FLAG_MOVE;
			if (g_freezeMode == 2 || g_freezeMode == 3) want |= FLAG_DISABLEMOTION; else want &= ~FLAG_DISABLEMOTION;
			if (g_ghost.isClone && g_cloneMotion) want &= ~FLAG_DISABLEMOTION; // 3t: el clon anima (no queda en T-pose)
			if (g_ghost.isClone && g_clearMask) want &= ~g_clearMask; // 3s: prueba de banderas (F5)
			if (want != flags)
			{
				SafeWrite(g_ghost.em + EM_FLAGS, &want, 4);
				if ((flags & FLAG_MOVE) != 0)
				{
					g_ghost.reFrozen++;
					if (g_ghost.reFrozen <= 5)
						Log("El juego le volvio a activar el movimiento al fantasma (vez %d); se lo quito de nuevo", g_ghost.reFrozen);
				}
			}
		}
		if (g_freezeMode >= 3)
		{
			if (!g_ghost.pinSet)
			{
				// Se guarda la rutina que tiene al terminar de inicializarse (el estado inicial, tranquilo) y se
				// mantiene fija: asi la IA nunca llega a la rutina en la que ataca (en las pruebas, r1=41 cerca de Leon).
				uint8_t cr[3] = { 0, 0, 0 };
				if (g_ghost.frames >= 3 &&
					SafeRead(g_ghost.em + 0xFD, &cr[0], 1) && SafeRead(g_ghost.em + 0xFE, &cr[1], 1) && SafeRead(g_ghost.em + 0xFF, &cr[2], 1))
				{
					memcpy(g_ghost.pinR, cr, 3);
					g_ghost.pinSet = true;
					Log("Modo %d: se fija la rutina del fantasma en r1=%u r2=%u r3=%u (tras %d frames)", g_freezeMode,
						(unsigned)cr[0], (unsigned)cr[1], (unsigned)cr[2], g_ghost.frames);
				}
			}
			else
			{
				SafeWrite(g_ghost.em + 0xFD, &g_ghost.pinR[0], 1);
				SafeWrite(g_ghost.em + 0xFE, &g_ghost.pinR[1], 1);
				SafeWrite(g_ghost.em + 0xFF, &g_ghost.pinR[2], 1);
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

	// 3w: animacion del otro jugador (antes de poner la posicion, porque la funcion de animacion puede mover un poco al personaje).
	if (g_ghost.isClone && g_testSlot == 4)
		MotionApply(snap, dt);

	SafeWrite(g_ghost.em + EM_POS, g_ghost.pos, sizeof(g_ghost.pos));
	SafeWrite(g_ghost.em + EM_ANG_Y, &g_ghost.yaw, sizeof(g_ghost.yaw));

	if (g_updateMatrix)
	{
		g_riskId = g_ghost.id;
		g_riskCode = 2;
		g_riskStart = GetTickCount();
		bool matOk = SafeMatUpdate(g_ghost.em);
		g_riskStart = 0;
		if (!matOk)
		{
			g_updateMatrix = false;
			Log("AVISO: fallo la actualizacion de la matriz del fantasma; se desactiva (actualizar_matriz=0)");
		}
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


// ---------------------------------------------------------------- panel de conexion (tecla F7)
// Una ventanita propia (en su propio hilo) para crear la partida o unirse sin reiniciar el juego.
// El panel solo deja un pedido en g_req; el hilo de red lo aplica (abre o cierra el socket).
struct ConnRequest
{
	bool pending;
	bool disconnect;
	bool host;
	char ip[64];
	int port;
};
static ConnRequest g_req;
static CRITICAL_SECTION g_reqLock;

static void ApplyConnRequest()
{
	ConnRequest r;
	EnterCriticalSection(&g_reqLock);
	if (!g_req.pending)
	{
		LeaveCriticalSection(&g_reqLock);
		return;
	}
	r = g_req;
	g_req.pending = false;
	LeaveCriticalSection(&g_reqLock);

	NetStop();
	if (r.disconnect)
	{
		Log("Panel F7: desconectado");
		return;
	}

	Config c;
	memset(&c, 0, sizeof(c));
	c.isHost = r.host;
	snprintf(c.ip, sizeof(c.ip), "%s", r.ip);
	c.port = r.port;
	Log("Panel F7: %s (ip='%s' puerto=%d)", r.host ? "crear partida (host)" : "unirse (client)", c.ip, c.port);
	g_netOk = NetInit(c);
	if (!g_netOk)
	{
		NetStop();
		Log("Panel F7: no se pudo abrir la conexion (mira los mensajes de arriba)");
	}
}

enum
{
	PID_RADIO_HOST = 301, PID_RADIO_JOIN, PID_LABEL_IP, PID_EDIT_IP, PID_LABEL_PORT, PID_EDIT_PORT,
	PID_BTN_CONNECT, PID_BTN_DISCONNECT, PID_STATUS, PID_HINT, PID_LIST
};
static const UINT WM_COOP_PANEL_TOGGLE = WM_APP + 0x4D;
static const UINT_PTR kPanelTimer = 7;
static volatile HWND g_panelWnd = nullptr;
static volatile LONG g_panelThreadStarted = 0;
static HWND p_radioHost, p_radioJoin, p_labelIp, p_editIp, p_editPort, p_status, p_list;

static HWND PanelControl(HWND parent, const char* cls, const char* text, DWORD style, DWORD ex, int x, int y, int w, int h, int id)
{
	HWND c = CreateWindowExA(ex, cls, text, WS_CHILD | WS_VISIBLE | style, x, y, w, h, parent,
		(HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
	if (c)
		SendMessageA(c, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
	return c;
}

static void PanelUpdateEnabled()
{
	bool join = SendMessageA(p_radioJoin, BM_GETCHECK, 0, 0) == BST_CHECKED;
	EnableWindow(p_labelIp, join);
	EnableWindow(p_editIp, join);
}

static void PanelUpdateStatus()
{
	char text[200];
	bool net = g_netOk;
	bool host = g_isHost;
	EnterCriticalSection(&g_remoteLock);
	bool connected = g_remote.connected;
	LeaveCriticalSection(&g_remoteLock);
	if (!net)
		snprintf(text, sizeof(text), "Estado: desconectado.");
	else if (host)
		snprintf(text, sizeof(text), connected ? "Estado: partida creada, tu amigo esta conectado." :
			"Estado: partida creada, esperando a tu amigo...");
	else
		snprintf(text, sizeof(text), connected ? "Estado: conectado al host." : "Estado: buscando al host...");
	SetWindowTextA(p_status, text);

	// Lista de jugadores conectados.
	char list[512];
	EnterCriticalSection(&g_remoteLock);
	RemoteState r = g_remote;
	LeaveCriticalSection(&g_remoteLock);
	int n = snprintf(list, sizeof(list), "Jugadores conectados:\r\n  1. Vos (%s)", host ? "host" : "cliente");
	if (net && r.connected)
	{
		DWORD secs = (GetTickCount() - r.firstConnectTick) / 1000;
		char ping[24];
		if (r.pingMs >= 0)
			snprintf(ping, sizeof(ping), "%d ms", r.pingMs);
		else
			snprintf(ping, sizeof(ping), "midiendo...");
		snprintf(list + n, sizeof(list) - n, "\r\n  2. Amigo - %s - ping %s - conectado hace %lu:%02lu - %s",
			r.peerText[0] ? r.peerText : "?", ping, (unsigned long)(secs / 60), (unsigned long)(secs % 60),
			(r.flags & FLAG_IN_GAME) ? "en juego" : "en menu");
	}
	else
	{
		snprintf(list + n, sizeof(list) - n, "\r\n  (nadie mas conectado)");
	}
	SetWindowTextA(p_list, list);
}

static void PanelConnect()
{
	bool host = SendMessageA(p_radioHost, BM_GETCHECK, 0, 0) == BST_CHECKED;
	char ipText[64];
	GetWindowTextA(p_editIp, ipText, sizeof(ipText));
	char portText[16];
	GetWindowTextA(p_editPort, portText, sizeof(portText));
	int port = atoi(portText);

	in_addr probe;
	if (!host && inet_pton(AF_INET, ipText, &probe) != 1)
	{
		SetWindowTextA(p_status, "La IP no es valida. Tiene que ser como 26.123.45.67 (la IP de Radmin del host).");
		return;
	}
	if (port < 1024 || port > 65535)
	{
		SetWindowTextA(p_status, "El puerto no es valido (usar entre 1024 y 65535, normalmente 27015).");
		return;
	}

	// Se guarda en el .ini para la proxima vez.
	char iniPath[MAX_PATH];
	if (ExeDirFile("re4coop.ini", iniPath, MAX_PATH))
	{
		WritePrivateProfileStringA("coop", "modo", host ? "host" : "client", iniPath);
		if (!host)
			WritePrivateProfileStringA("coop", "ip", ipText, iniPath);
		WritePrivateProfileStringA("coop", "puerto", portText, iniPath);
	}

	EnterCriticalSection(&g_reqLock);
	g_req.pending = true;
	g_req.disconnect = false;
	g_req.host = host;
	snprintf(g_req.ip, sizeof(g_req.ip), "%s", host ? "" : ipText);
	g_req.port = port;
	LeaveCriticalSection(&g_reqLock);
	SetWindowTextA(p_status, "Conectando...");
}

static void PanelDisconnect()
{
	EnterCriticalSection(&g_reqLock);
	g_req.pending = true;
	g_req.disconnect = true;
	LeaveCriticalSection(&g_reqLock);
}

static LRESULT CALLBACK PanelProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case PID_RADIO_HOST:
		case PID_RADIO_JOIN:
			PanelUpdateEnabled();
			return 0;
		case PID_BTN_CONNECT:
			PanelConnect();
			return 0;
		case PID_BTN_DISCONNECT:
			PanelDisconnect();
			return 0;
		}
		break;
	case WM_TIMER:
		if (wParam == kPanelTimer && IsWindowVisible(hwnd))
			PanelUpdateStatus();
		return 0;
	case WM_COOP_PANEL_TOGGLE:
		if (IsWindowVisible(hwnd))
		{
			ShowWindow(hwnd, SW_HIDE);
			if (g_hwnd)
				SetForegroundWindow(g_hwnd);
		}
		else
		{
			PanelUpdateStatus();
			ShowWindow(hwnd, SW_SHOW);
			SetForegroundWindow(hwnd);
		}
		return 0;
	case WM_CLOSE:
		ShowWindow(hwnd, SW_HIDE); // la X solo oculta el panel
		if (g_hwnd)
			SetForegroundWindow(g_hwnd);
		return 0;
	}
	return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static DWORD WINAPI PanelThread(LPVOID)
{
	WNDCLASSA wc;
	memset(&wc, 0, sizeof(wc));
	wc.lpfnWndProc = PanelProc;
	wc.hInstance = GetModuleHandleA(nullptr);
	wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
	wc.hbrBackground = (HBRUSH)(INT_PTR)(COLOR_BTNFACE + 1);
	wc.lpszClassName = "RE4CoopPanel";
	RegisterClassA(&wc);

	HWND w = CreateWindowExA(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, "RE4CoopPanel", "RE4 Coop - Conexion (F7)",
		WS_POPUP | WS_CAPTION | WS_SYSMENU, 40, 40, 380, 340, nullptr, nullptr, wc.hInstance, nullptr);
	if (!w)
	{
		Log("AVISO: no se pudo crear la ventana del panel F7");
		return 0;
	}

	p_radioHost = PanelControl(w, "BUTTON", "Crear partida (yo soy el host)", BS_AUTORADIOBUTTON | WS_GROUP | WS_TABSTOP, 0, 14, 12, 340, 22, PID_RADIO_HOST);
	p_radioJoin = PanelControl(w, "BUTTON", "Unirme a la partida de mi amigo", BS_AUTORADIOBUTTON, 0, 14, 36, 340, 22, PID_RADIO_JOIN);
	p_labelIp = PanelControl(w, "STATIC", "IP de Radmin del host:", SS_LEFT, 0, 14, 70, 140, 18, PID_LABEL_IP);
	p_editIp = PanelControl(w, "EDIT", "", ES_AUTOHSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE, 160, 66, 194, 22, PID_EDIT_IP);
	PanelControl(w, "STATIC", "Puerto:", SS_LEFT, 0, 14, 100, 140, 18, PID_LABEL_PORT);
	p_editPort = PanelControl(w, "EDIT", "27015", ES_AUTOHSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE, 160, 96, 80, 22, PID_EDIT_PORT);
	PanelControl(w, "BUTTON", "Conectar", BS_DEFPUSHBUTTON | WS_TABSTOP, 0, 14, 132, 160, 30, PID_BTN_CONNECT);
	PanelControl(w, "BUTTON", "Desconectar", BS_PUSHBUTTON | WS_TABSTOP, 0, 194, 132, 160, 30, PID_BTN_DISCONNECT);
	p_status = PanelControl(w, "STATIC", "", SS_LEFT, 0, 14, 172, 346, 34, PID_STATUS);
	p_list = PanelControl(w, "STATIC", "", SS_LEFT, 0, 14, 212, 346, 78, PID_LIST);
	PanelControl(w, "STATIC", "F7 muestra/oculta este panel. La X solo lo oculta.", SS_LEFT, 0, 14, 300, 346, 18, PID_HINT);

	// Valores de la ultima vez (del .ini).
	bool host = g_isHost;
	char ip[64] = "";
	int port = 27015;
	char iniPath[MAX_PATH];
	if (ExeDirFile("re4coop.ini", iniPath, MAX_PATH))
	{
		GetPrivateProfileStringA("coop", "ip", "", ip, sizeof(ip), iniPath);
		port = (int)GetPrivateProfileIntA("coop", "puerto", 27015, iniPath);
	}
	SendMessageA(host ? p_radioHost : p_radioJoin, BM_SETCHECK, BST_CHECKED, 0);
	SetWindowTextA(p_editIp, ip);
	char portText[16];
	snprintf(portText, sizeof(portText), "%d", port);
	SetWindowTextA(p_editPort, portText);
	PanelUpdateEnabled();
	PanelUpdateStatus();

	SetTimer(w, kPanelTimer, 500, nullptr);
	g_panelWnd = w;
	ShowWindow(w, SW_SHOW);
	SetForegroundWindow(w);
	Log("Panel F7 abierto");

	MSG m;
	while (GetMessageA(&m, nullptr, 0, 0) > 0)
	{
		if (!IsDialogMessageA(w, &m))
		{
			TranslateMessage(&m);
			DispatchMessageA(&m);
		}
	}
	return 0;
}

static void TogglePanel()
{
	if (InterlockedCompareExchange(&g_panelThreadStarted, 1, 0) == 0)
	{
		HANDLE h = CreateThread(nullptr, 0, PanelThread, nullptr, 0, nullptr);
		if (h)
			CloseHandle(h);
		return;
	}
	HWND w = g_panelWnd;
	if (w)
		PostMessageA(w, WM_COOP_PANEL_TOGGLE, 0, 0);
}

static bool g_f7Prev = false;
static bool g_f8Prev = false;
static bool g_f9Prev = false;
static bool g_f10Prev = false;
static bool g_f11Prev = false;
static bool g_f6Prev = false;
static bool g_f5Prev = false;
static bool g_f3Prev = false;
static bool g_f4Prev = false;
static int g_maskIdx = 0;

static void HandleHotkeys()
{
	// Solo cuando la ventana del juego tiene el foco (si no, escribir en otra ventana activaria cosas).
	bool focused = (GetForegroundWindow() == g_hwnd);
	bool f7 = focused && (GetAsyncKeyState(VK_F7) & 0x8000) != 0;
	if (f7 && !g_f7Prev)
		TogglePanel();
	g_f7Prev = f7;
	bool f4 = focused && (GetAsyncKeyState(VK_F4) & 0x8000) != 0 && !(GetAsyncKeyState(VK_MENU) & 0x8000); // Alt+F4 cierra el juego: no se toma como tecla del mod
	if (f4 && !g_f4Prev)
	{
		g_autoFreezeMove = !g_autoFreezeMove;
		if (!g_autoFreezeMove) { g_testSlot = -1; g_testIdx = 0; ApplyTestSlot(); }
		else if (g_ghost.em && g_ghost.isClone) { g_testSlot = 4; g_testIdx = 1; ApplyTestSlot(); }
		Log("F4: anular move() del clon automaticamente = %s", g_autoFreezeMove ? "SI" : "NO");
		Beep(g_autoFreezeMove ? 800 : 350, 120);
	}
	g_f4Prev = f4;
	static bool s_f2Prev = false;
	bool f2 = focused && (GetAsyncKeyState(VK_F2) & 0x8000) != 0;
	if (f2 && !s_f2Prev)
	{
		// 0 = sin animacion, 1 = solo escribir datos, 2 = evaluar las dos capas, 3 = evaluar solo la capa principal
		int mode = !g_motApply ? 0 : (!g_motEval ? 1 : (g_motSubEval ? 2 : 3));
		mode = (mode + 1) % 4;
		g_motApply = mode >= 1;
		g_motEval = mode >= 2;
		g_motSubEval = (mode != 3);
		Log("F2: animacion del clon = modo %d (%s)", mode, mode == 0 ? "apagada" : (mode == 1 ? "solo escribir datos" : (mode == 2 ? "evaluar las dos capas" : "evaluar solo la capa principal")));
		Beep(350 + mode * 200, 120);
	}
	s_f2Prev = f2;
	bool f3 = focused && (GetAsyncKeyState(VK_F3) & 0x8000) != 0;
	if (f3 && !g_f3Prev)
	{
		g_cloneMotion = !g_cloneMotion;
		Log("F3: el clon %s", g_cloneMotion ? "ANIMA (sin bandera de congelado)" : "queda CONGELADO (T-pose)");
		Beep(g_cloneMotion ? 900 : 400, 120);
	}
	g_f3Prev = f3;
	bool f5 = focused && (GetAsyncKeyState(VK_F5) & 0x8000) != 0;
	if (f5 && !g_f5Prev)
	{
		static const uint32_t kMasks[] = { 0, 0x04000000, 0x02000000, 0x01000000, 0x07000000, 0x00002000, 0x00000040, 0x00000010, 0x00000004, 0x00000002 };
		const int n = (int)(sizeof(kMasks) / sizeof(kMasks[0]));
		g_maskIdx = (g_maskIdx + 1) % n;
		g_clearMask = kMasks[g_maskIdx];
		uint32_t fl = 0;
		if (g_ghost.em && SafeRead(g_ghost.em + EM_FLAGS, &fl, 4))
		{
			fl &= ~g_clearMask;
			SafeWrite(g_ghost.em + EM_FLAGS, &fl, 4);
		}
		Log("F5: bits que se le borran al clon = 0x%08X (prueba %d de %d)", (unsigned)g_clearMask, g_maskIdx, n - 1);
		Beep(500 + g_maskIdx * 40, 120);
	}
	g_f5Prev = f5;
	bool f6 = focused && (GetAsyncKeyState(VK_F6) & 0x8000) != 0;
	if (f6 && !g_f6Prev)
	{
		static const int kSeq[] = { -1, 4, 12, 7, 20, 21, 9, 8, 19, 99 };
		const int n = (int)(sizeof(kSeq) / sizeof(kSeq[0]));
		bool back = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
		for (int tries = 0; tries < n; tries++)
		{
			g_testIdx = (g_testIdx + (back ? n - 1 : 1)) % n;
			int sl = kSeq[g_testIdx];
			if (sl < 0 || sl == 99 || !g_vtReady || g_slotRet[sl] >= 0)
				break;
		}
		g_testSlot = kSeq[g_testIdx];
		ApplyTestSlot();
		Log("F6: funcion anulada para el clon = %d (%s)", g_testSlot, g_testSlot < 0 ? "ninguna" : (g_testSlot == 99 ? "todas las seguras" : "solo esa"));
		Beep(300 + g_testIdx * 30, 120);
	}
	g_f6Prev = f6;
	bool f8 = focused && (GetAsyncKeyState(VK_F8) & 0x8000) != 0;
	bool f9 = focused && (GetAsyncKeyState(VK_F9) & 0x8000) != 0;
	bool f10 = focused && (GetAsyncKeyState(VK_F10) & 0x8000) != 0;
	bool f11 = focused && (GetAsyncKeyState(VK_F11) & 0x8000) != 0;

	if (f11 && !g_f11Prev)
	{
		int leonId = -1, ashId = -1;
		bool haveLeon = ReadActorId(g_plGlobal, &leonId);
		bool haveAsh = ReadActorId(g_asGlobal, &ashId);
		Log("F11: ids reales en memoria: Leon=%s0x%02X Ashley=%s0x%02X", haveLeon ? "" : "(no leido) ", haveLeon ? leonId : 0,
			haveAsh ? "" : "(no leido) ", haveAsh ? ashId : 0);
		g_skinMode = (g_skinMode + 1) % 2;
		// 3l: en vez del Leon jugador (0x00, que pelea por la camara y copia tus controles), se prueba el id 0x02
		// ("Leon de eventos", el de las escenas: no tiene logica de jugador ni lee el control).
		if (g_skinMode == 1) g_forceId = 0x00;
		else { g_forceId = -1; g_skinMode = 0; }
		g_spawnFails = 0;
		Log("F11: skin de prueba = %s", g_skinMode == 0 ? "Ganado (copia del enemigo)" : "clon de Leon (id 0x00)");
		GhostDespawn();
		MessageBeep(MB_OK);
	}
	g_f11Prev = f11;

	if (f8 && !g_f8Prev)
	{
		g_ghostEnabled = !g_ghostEnabled;
		g_spawnFails = 0;
		Log("F8: fantasma %s", g_ghostEnabled ? "ACTIVADO" : "DESACTIVADO");
		if (g_ghostEnabled)
		{
			ScanCandidates();
			if (g_candCount == 0)
				Log("AVISO: ahora no hay ningun enemigo compatible vivo en esta sala, asi que no hay modelo para copiar. "
					"El fantasma aparecera solo cuando haya uno (por ejemplo, cerca de los primeros Ganados).");
		}
		MessageBeep(g_ghostEnabled ? MB_ICONASTERISK : MB_ICONHAND);
		if (!g_ghostEnabled)
			GhostDespawn();
	}

	if (f9 && !g_f9Prev)
	{
		ScanCandidates();
		if (g_candCount == 0)
		{
			Log("F9: no hay modelos disponibles en esta sala (no hay enemigos compatibles vivos)");
			MessageBeep(MB_ICONHAND);
		}
		else
		{
			g_candIndex = (g_candIndex + 1) % g_candCount;
			g_wantedId = g_cands[g_candIndex].id;
			g_spawnFails = 0;
			Log("F9: modelo del fantasma = 0x%02X (%s), %d de %d disponibles",
				g_wantedId, ModelName(g_wantedId), g_candIndex + 1, g_candCount);
			MessageBeep(MB_OK);
			GhostDespawn();
		}
	}

	g_f8Prev = f8;
	if (f10 && !g_f10Prev)
	{
		g_freezeMode = g_freezeMode % 4 + 1;
		// El fantasma se vuelve a crear con el modo nuevo (cambiar las banderas de uno ya creado puede colgar el juego).
		g_spawnFails = 0;
		GhostDespawn();
		Log("F10: modo de inmovilizacion del fantasma = %d (%s)", g_freezeMode,
			g_freezeMode == 1 ? "solo sin movimiento" : g_freezeMode == 2 ? "sin movimiento y sin animacion" :
			g_freezeMode == 3 ? "sin movimiento, sin animacion y rutina fija" : "sin movimiento y rutina fija, con animacion");
		MessageBeep(MB_OK);
	}

	g_f9Prev = f9;
	g_f10Prev = f10;
}

static void GhostUpdate(float dt)
{
	uint8_t rno0 = 0;
	uint16_t room = 0;
	uint32_t frame = 0;
	DWORD now = GetTickCount();

	if (!ReadGameState(&rno0, &room, &frame))
		return;

	// Prueba de skin: si el juego vuelve a poner al clon como "Leon", se lo devolvemos al verdadero.
	if (g_ghost.em && g_realLeon && g_plGlobal)
	{
		uintptr_t cur = 0;
		if (SafeRead(g_plGlobal, &cur, 4) && cur == g_ghost.em)
		{
			SafeWrite(g_plGlobal, &g_realLeon, 4);
			g_leonRestores++;
			if (g_leonRestores <= 5 || g_leonRestores % 600 == 0)
				Log("PRUEBA DE SKIN: el puntero de Leon apuntaba al clon, se devolvio al verdadero (veces: %d)", g_leonRestores);
		}
	}

	// 3t: si la camara se pega al clon, se la devolvemos a Leon en cada tick.
	if (g_ghost.em && g_ghost.isClone)
		CamRestore(g_ghost.em);

	// 3v: si el juego le devuelve al clon la tabla de funciones original, se la volvemos a poner (si no, move() vuelve a correr).
	if (g_ghost.em && g_ghost.isClone && g_vtReady)
	{
		uint32_t vt = 0;
		uint32_t mine = (uint32_t)(uintptr_t)g_vtCopy;
		if (SafeRead(g_ghost.em, &vt, 4) && vt != mine)
		{
			SafeWrite(g_ghost.em, &mine, 4);
			static int s_vtFixes = 0;
			s_vtFixes++;
			if (s_vtFixes <= 10 || s_vtFixes % 300 == 0)
				Log("CLON: el juego le habia cambiado la tabla de funciones (0x%08X); se la volvi a poner (veces: %d)", (unsigned)vt, s_vtFixes);
		}
	}

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

	// Cada medio segundo, mientras el juego esta en su bucle principal, se actualiza la lista de modelos disponibles
	// (asi el log siempre dice que hay en la sala, aunque el fantasma este apagado).
	static DWORD s_nextScan = 0;
	if (rno0 == RNO0_MAINLOOP && (int)(now - s_nextScan) >= 0)
	{
		s_nextScan = now + 500;
		ScanCandidates();
	}

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
		if (!g_ghost.em && g_candCount == 0 && !g_warnedNoCand)
		{
			g_warnedNoCand = true;
			Log("Esperando: no hay enemigos compatibles vivos en esta sala para copiar su modelo.");
		}
		if (g_candCount > 0)
			g_warnedNoCand = false;
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
	Log("RE4 Coop - hito 3z2 (v5 diagnostico de partes del cuerpo) iniciado");
	InitializeCriticalSection(&g_remoteLock);
	InitializeCriticalSection(&g_reqLock);

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
		g_camCtrl = FindGlobalPointer("Camara (CamCtrl)", "D9 EE B9 ? ? ? ? D9 9E A4 00 00 00 E8 ? ? ? ? D9 EE", 3);
		FindMotionMove();
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
	g_netOk = false;
	Config cfg;
	bool cfgOk = LoadConfig(cfg);
	if (cfgOk)
		g_netOk = NetInit(cfg);
	if (!g_netOk)
		Log("AVISO: sin conexion. Revisa re4coop.ini y los mensajes de arriba.");

	// Fantasma: modelo preferido y enganche de la ventana.
	g_wantedId = (uint8_t)(cfgOk ? cfg.modelId : 0x10);
	g_updateMatrix = cfgOk ? cfg.updateMatrix : true;
	g_killOnHang = cfgOk ? cfg.killOnHang : true;
	g_ghostEnabled = cfgOk && cfg.ghostOnStart && ghostPossible;
	if (cfgOk && cfg.leonClone) { g_skinMode = 1; g_forceId = 0x00; }
	Log("Tipo de fantasma: %s (F11 cambia entre clon de Leon y Ganado)", g_forceId >= 0 ? "clon de Leon (aparece solo, sin enemigos)" : "Ganado (necesita un enemigo vivo)");
	Log("Modelo preferido del fantasma: 0x%02X (%s). Solo se crea si ya hay un enemigo igual vivo en la sala. "
		"Teclas: F8 = activar/desactivar, F9 = cambiar entre los modelos disponibles.",
		g_wantedId, ModelName(g_wantedId));
	Log("Tecla de emergencia: mantener Ctrl + Shift + F12 durante 2 segundos cierra el juego. "
		"Cierre automatico si se cuelga al crear el fantasma: %s.", g_killOnHang ? "ACTIVADO" : "desactivado");

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
	bool hangReported = false;
	DWORD panicStart = 0;

	for (;;)
	{
		Sleep(2);
		ApplyConnRequest();
		DWORD now = GetTickCount();

		// Vigilancia: si el juego lleva mucho tiempo dentro de una llamada arriesgada, esta colgado. Este hilo
		// sigue funcionando aunque el juego no, asi que puede anotarlo en el log y cerrar el juego solo
		// (en pantalla completa un juego colgado puede dejar la pantalla congelada, sin acceso al Administrador de tareas).
		DWORD riskStart = g_riskStart;
		if (riskStart != 0)
		{
			// La hora se lee DESPUES de leer riskStart. Con la hora leida antes (now), si el juego empezaba la llamada
			// justo en el medio, la resta daba un numero enorme y se habria cerrado el juego sin estar colgado.
			DWORD waited = GetTickCount() - riskStart;
			int code = g_riskCode;
			int rid = g_riskId;
			if (waited > 4000 && !hangReported)
			{
				hangReported = true;
				Log("COLGADO: el juego no volvio de %s (modelo 0x%02X) en mas de 4 segundos.%s",
					code == 1 ? "EmSetEvent (crear el personaje)" : "matUpdate (actualizar la matriz del personaje)",
					(unsigned)rid,
					g_killOnHang ? " Se cierra solo en unos segundos." : " Hay que cerrarlo desde el Administrador de tareas.");
			}
			// Solo se cierra si SIGUE dentro de la misma llamada que empezo hace mas de 7 segundos.
			if (waited > 7000 && g_killOnHang && g_riskStart == riskStart)
			{
				Log("Cerrando el juego automaticamente (cerrar_si_se_cuelga=1). Mandame este log.");
				TerminateProcess(GetCurrentProcess(), 1);
			}
		}

		// Tecla de emergencia: mantener Ctrl + Shift + F12 durante 2 segundos cierra el juego al instante.
		// Sirve aunque el juego este colgado (este hilo sigue funcionando) y aunque la ventana no tenga el foco.
		bool panicKeys = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0 && (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0 &&
			(GetAsyncKeyState(VK_F12) & 0x8000) != 0;
		if (panicKeys)
		{
			DWORD t = GetTickCount();
			if (panicStart == 0)
				panicStart = t;
			else if (t - panicStart >= 2000)
			{
				Log("TECLA DE EMERGENCIA: se cierra el juego (Ctrl+Shift+F12 mantenido 2 segundos).");
				TerminateProcess(GetCurrentProcess(), 1);
			}
		}
		else
			panicStart = 0;

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
		if (g_netOk && now - lastNet >= 50)
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
			{
				DWORD t = GetTickCount();
				p.tickSend = (uint32_t)t;
				EnterCriticalSection(&g_remoteLock);
				p.echoTick = g_remote.theirTick;
				DWORD delay = g_remote.theirTick ? (t - g_remote.theirTickAt) : 0;
				LeaveCriticalSection(&g_remoteLock);
				p.echoDelay = (uint16_t)(delay > 65535 ? 65535 : delay);
			}
			if (leonOk)
			{
				memcpy(p.pos, leon.pos, sizeof(p.pos));
				p.yaw = leon.angY;
				ReadMotion(leon.obj, &p.mot);
				ReadMotionAt(leon.obj, EM_SUBMOT, &p.sub);
			}
			NetSend(p);
			NetReceive();
			NetCheckTimeout();
		}

		// Una vez por segundo: resumen en el log.
		if (now - lastLog < 1000)
			continue;
		lastLog = now;

		if (g_ghost.em && g_ghost.isClone)
		{
			CamLog("periodico");
			CamDiag();
			MotionLog();
		}
		leonOk = ReadPlayer(g_plGlobal, &leon);
		if (leonOk)
		{
			uint32_t lFlags = 0;
			int16_t lHp = 0;
			uint8_t lR0 = 0;
			SafeRead(leon.obj + 0x04, &lFlags, 4);
			SafeRead(leon.obj + 0x324, &lHp, 2);
			SafeRead(leon.obj + EM_RNO0, &lR0, 1);
			int16_t vidaCur = 0, vidaMax = 0;
			ReadPlayerHp(&vidaCur, &vidaMax);
			Log("Leon    @0x%08X pos=(%.1f, %.1f, %.1f) giro=%.2f sala=0x%04X flags=0x%08X vida=%d/%d r0=%u",
				(unsigned)leon.obj, leon.pos[0], leon.pos[1], leon.pos[2], leon.angY, (unsigned)ReadRoomNow(),
				(unsigned)lFlags, (int)vidaCur, (int)vidaMax, (unsigned)lR0);
			char det[240];
			DescribeEm(leon.obj, det, sizeof(det));
			Log("  Leon detalle: %s", det);
			{
				char dump[0x90 * 3 + 8];
				HexDump(leon.obj + 0x1D8, 0x90, dump, sizeof(dump));
				Log("  Leon movimiento[1D8..268]: %s", dump);
			}
			if (g_ghost.em)
			{
				uint32_t gFlags = 0;
				uint8_t gR0 = 0;
				SafeRead(g_ghost.em + EM_FLAGS, &gFlags, 4);
				SafeRead(g_ghost.em + EM_RNO0, &gR0, 1);
				float ddx = g_ghost.pos[0] - leon.pos[0], ddz = g_ghost.pos[2] - leon.pos[2];
				Log("Fantasma flags=0x%08X r0=%u distancia_a_Leon=%.0f reactivaciones=%d modo=%d",
					(unsigned)gFlags, (unsigned)gR0, sqrtf(ddx * ddx + ddz * ddz), g_ghost.reFrozen, g_freezeMode);
				DescribeEm(g_ghost.em, det, sizeof(det));
				Log("  Fantasma detalle: %s", det);
				{
					char dump[0x90 * 3 + 8];
					HexDump(g_ghost.em + 0x1D8, 0x90, dump, sizeof(dump));
					Log("  Fantasma movimiento[1D8..268]: %s", dump);
				}
			}
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

		if (g_netOk)
		{
			EnterCriticalSection(&g_remoteLock);
			RemoteState r = g_remote;
			g_remote.packetsThisSecond = 0;
			LeaveCriticalSection(&g_remoteLock);

			if (r.connected)
			{
				Log("AMIGO   %s pos=(%.1f, %.1f, %.1f) giro=%.2f sala=0x%04X paquetes/s=%d ping=%d ms",
					(r.flags & FLAG_IN_GAME) ? "en juego" : "en menu  ",
					r.pos[0], r.pos[1], r.pos[2], r.yaw, (unsigned)r.room, r.packetsThisSecond, r.pingMs);
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
			Log("ESTADO  ticks=%d frames=%u fantasma=%s%s modelo=0x%02X disponibles=%d rno0=%u anulada=%d bits=0x%08X",
				g_tickCount, (unsigned)(frame - lastFrame),
				g_ghostEnabled ? "ON" : "off", g_ghost.em ? " (creado)" : "",
				(unsigned)g_wantedId, g_candCount, (unsigned)rno0, g_testSlot, (unsigned)g_clearMask);
			lastFrame = frame;
			g_tickCount = 0;
		}
	}
}
