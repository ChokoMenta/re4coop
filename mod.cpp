// RE4 Coop - hito 1: comprobar que enganchamos bien el juego.
//
// Que hace:
//  1. Busca en la memoria del juego dos "punteros" (usando los mismos patrones de bytes
//     que usa el proyecto re4_tweaks): uno apunta a Leon y otro a Ashley.
//  2. Cada segundo escribe en re4coop.log (junto a bio4.exe) donde estan Leon y Ashley.
//
// Si ese archivo muestra posiciones que cambian cuando caminas, el hito 1 funciona.

#include <windows.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

// ---------------------------------------------------------------- log

static FILE* g_log = nullptr;

static void LogOpen()
{
	char path[MAX_PATH];
	DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
	if (n == 0 || n >= MAX_PATH)
		return;

	// Reemplaza "bio4.exe" por "re4coop.log" (misma carpeta).
	char* slash = strrchr(path, '\\');
	if (!slash)
		return;
	slash[1] = '\0';
	lstrcatA(path, "re4coop.log");

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
	float pos[3];   // cCoord::pos_94
	float world[3]; // cCoord::world_70
	float angY;     // cCoord::ang_A0.y
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
		memcpy(out->world, (void*)(obj + 0x70), sizeof(out->world));
		memcpy(&out->angY, (void*)(obj + 0xA0 + 4), sizeof(out->angY));
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
}

// ---------------------------------------------------------------- principal

void ModMain()
{
	LogOpen();
	Log("RE4 Coop - hito 1 iniciado");

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

	bool lastLeonValid = false;
	for (;;)
	{
		Sleep(1000);

		PlayerInfo leon = {};
		bool leonOk = ReadPlayer(plGlobal, &leon);

		if (leonOk)
		{
			Log("Leon    @0x%08X pos=(%.1f, %.1f, %.1f) world=(%.1f, %.1f, %.1f) giro=%.2f",
				(unsigned)leon.obj, leon.pos[0], leon.pos[1], leon.pos[2],
				leon.world[0], leon.world[1], leon.world[2], leon.angY);
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
	}
}
