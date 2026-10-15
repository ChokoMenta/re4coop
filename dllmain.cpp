// RE4 Coop - punto de entrada.
// Este archivo se hace pasar por dinput8.dll: el juego lo carga al arrancar,
// y desde aca reenviamos todo al dinput8.dll real de Windows para que el
// control/teclado sigan funcionando normal. Ademas lanzamos nuestro propio hilo.

#include <windows.h>
#include <unknwn.h>

void ModMain(); // definido en mod.cpp

typedef HRESULT(WINAPI* DirectInput8Create_t)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);

static HMODULE g_realDinput = nullptr;
static DirectInput8Create_t g_realCreate = nullptr;

static bool LoadRealDinput()
{
	if (g_realCreate)
		return true;

	char path[MAX_PATH];
	UINT n = GetSystemDirectoryA(path, MAX_PATH);
	if (n == 0 || n > MAX_PATH - 16)
		return false;

	lstrcatA(path, "\\dinput8.dll");
	g_realDinput = LoadLibraryA(path);
	if (!g_realDinput)
		return false;

	g_realCreate = (DirectInput8Create_t)GetProcAddress(g_realDinput, "DirectInput8Create");
	return g_realCreate != nullptr;
}

// Se exporta con el archivo dinput8.def (sin decoracion de nombre).
extern "C" HRESULT WINAPI DirectInput8Create(HINSTANCE hinst, DWORD ver, REFIID riid, LPVOID* out, LPUNKNOWN outer)
{
	if (!LoadRealDinput())
		return E_FAIL;

	return g_realCreate(hinst, ver, riid, out, outer);
}

static DWORD WINAPI ModThread(LPVOID)
{
	ModMain();
	return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(module);

		// No se hace trabajo pesado dentro de DllMain: se lanza un hilo aparte.
		HANDLE thread = CreateThread(nullptr, 0, ModThread, nullptr, 0, nullptr);
		if (thread)
			CloseHandle(thread);
	}
	return TRUE;
}
