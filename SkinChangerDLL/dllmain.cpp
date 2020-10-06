//author https://github.com/autergame
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <locale.h>
#include <windows.h>
#include <vector>

DWORD findsignature(const char** pattern, uint32_t arraylength, BOOL read)
{
	HMODULE module = GetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)module + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER textSection = IMAGE_FIRST_SECTION(ntHeaders);
	for (uint32_t o = 0; o < arraylength; o++)
	{
		std::vector<int> bytes;
		for (size_t i = 0; i < strlen(pattern[o]); i++)
		{
			if (pattern[o][i] == '?')
				bytes.push_back(-1);
			else
				bytes.push_back((uint8_t)strtoul(pattern[o]+i, NULL, 16));
			i += 2;
		}
		int* data = bytes.data();
		size_t size = bytes.size();

		DWORD sizeOfImage = textSection->SizeOfRawData;
		uint8_t* scanBytes = (uint8_t*)module + textSection->VirtualAddress;

		MEMORY_BASIC_INFORMATION mbi = { 0 };
		uint8_t* next_check_address = 0;

		uint8_t* address = NULL;
		for (DWORD i = 0; i < sizeOfImage - size; ++i)
		{
			BOOL found = 1;
			for (DWORD j = 0; j < size; ++j)
			{
				uint8_t* current_address = scanBytes + i + j;
				if (current_address >= next_check_address)
				{
					if (!VirtualQuery((void*)current_address, &mbi, sizeof(mbi)))
						break;

					if (mbi.Protect == PAGE_NOACCESS) {
						i += ((DWORD)mbi.BaseAddress + mbi.RegionSize) - ((DWORD)scanBytes + i);
						i--;
						found = 0;
						break;
					}
					else {
						next_check_address = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
					}
				}

				if ((scanBytes[i + j] != data[j]) && (data[j] != -1)) {
					found = 0;
					break;
				}
			}
			if (found)
			{
				address = &scanBytes[i];
				break;
			}
		}

		if (!address)
			continue;

		if (read)
			address = *(uint8_t**)(address + (((DWORD)strchr(pattern[o], '?') - (DWORD)pattern[o]) / 3));
		else if (address[0] == 0xE8)
			address = address + *(uint32_t*)(address + 1) + 5;

		return (DWORD)address;
	}
	return NULL;
}

typedef struct riot_string
{
	char* string;
	uint32_t length;
	uint32_t capacity;
} riot_string;

typedef struct character_data 
{
	riot_string model;
	int32_t skin;
	uint8_t _pad0[0x20];
	uint8_t update_spells;
	uint8_t dont_update_hud;
	uint8_t change_particle;
	uint8_t _pad1[0x01];
	uint8_t _pad2[0x0C];
} character_data;

typedef struct character_data_stack
{
	character_data* stack;
	uint8_t _pad0[0x8];
	character_data base_skin;
} character_data_stack;

typedef struct game_client
{
	uint8_t _pad0[0x8];
	int32_t game_state;
} game_client;

class xor_value
{
public:
	uint8_t xor_key_was_init = 0;
	uint8_t bytes_xor_count;
	uint8_t bytes_xor_count_8;
	int32_t xor_key;
	uint8_t value_index = 0;
	int32_t values_table[3];
	void encrypt(int32_t value)
	{
		if (!xor_key_was_init)
		{
			bytes_xor_count_8 = 0;
			bytes_xor_count = 1;

			auto key = __rdtsc();
			for (int i = 0; i < 4; i++)
				*((unsigned char*)(&xor_key) + i) = *((unsigned char*)(&key) + i);

			value_index = 0;
			xor_key_was_init = 1;
		}
		int32_t xored_value = value;
		int32_t xor_key_value = xor_key;
		{
			uint32_t* xor_value_ptr = (uint32_t*)(&xor_key_value);
			*((uint32_t*)(&xored_value)) ^= ~xor_value_ptr[0];

		}
		auto new_value_index = uint8_t(value_index + 1) % 3;
		values_table[new_value_index] = xored_value;
		value_index = new_value_index;
	}
};

HANDLE connectpipe(const char* pipename)
{
	HANDLE hPipe = CreateFileA(pipename,
		GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hPipe != INVALID_HANDLE_VALUE)
		return hPipe;
	while (1)
	{
		hPipe = CreateFileA(pipename,
			GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe != INVALID_HANDLE_VALUE)
			break;
		if (GetLastError() != ERROR_PIPE_BUSY)
		{
			printf("Could not open pipe %d\n", GetLastError());
			return INVALID_HANDLE_VALUE;
		}
		WaitNamedPipeA(pipename, 100);
	}
	return hPipe;
}

typedef struct champ
{
	char alias[32];
	uint8_t id;
} champ;

void waitgame(game_client* client)
{
	while (client == NULL || client->game_state != 2)
	{
		Sleep(100);
	}
	Sleep(1000);
}

//#define DEBUGSkin

DWORD init(HMODULE mymodule)
{ 
	const char* skididsignature[1] = {
		"80 BE ?? ?? ?? ?? ?? 75 50 0F 31 33 C9 66 C7 86 ?? ?? ?? ?? ?? ?? 89 44 24 18"
	};
	const char* playersignature[3] =  {
		"8B 0D ?? ?? ?? ?? 8B F8 81 C1 ?? ?? ?? ?? 57",
		"A1 ?? ?? ?? ?? 85 C0 74 18 84 C9",
		"8B 0D ?? ?? ?? ?? 8D 54 24 14 8B 3D"
	};
	const char* gameclientsignature[2] = {
		"A1 ?? ?? ?? ?? 83 C4 04 C6 40 36 15",
		"8B 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 C7 44 24 ?? ?? ?? ?? ?? 89 44 24 18"
	};
	const char* characterdatastacksignature[1] = {
		"8D 8E ?? ?? ?? ?? FF 74 24 58"
	};
	const char* characterdatastackupdatesignature[2] = {
		"83 EC 18 53 56 57 8D 44 24 20",
		"E8 ?? ?? ?? ?? 8D 4C 24 14 E8 ?? ?? ?? ?? 8B 07"
	};

	DWORD skididsig = findsignature(skididsignature, 1, 1);
	DWORD playersig = findsignature(playersignature, 3, 1);
	DWORD gameclientsig = findsignature(gameclientsignature, 2, 1);
	DWORD characterdatastacksig = findsignature(characterdatastacksignature, 1, 1);
	DWORD characterdatastackupdatesig = findsignature(characterdatastackupdatesignature, 2, 0);

	auto Update = (void(__thiscall*)(void*, uint8_t))(characterdatastackupdatesig);
	waitgame(*(game_client**)(gameclientsig));

#ifdef DEBUGSkin
	AllocConsole();
	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);
	setlocale(LC_ALL, "");
#endif

	champ* champi = (champ*)calloc(sizeof(champ), 1);
	HANDLE pipe = connectpipe("\\\\.\\pipe\\skinchangerpipe");
	while (pipe != INVALID_HANDLE_VALUE)
	{
		if (ReadFile(pipe, champi, sizeof(champ), NULL, NULL) == TRUE)
		{
			waitgame(*(game_client**)(gameclientsig));
			uint8_t* player = *(uint8_t**)(playersig);
			if (player)
			{
				character_data_stack* cds = (character_data_stack*)(player + characterdatastacksig);
				if (strcmp(cds->base_skin.model.string, champi->alias) == 0)
				{
					((xor_value*)(player + skididsig))->encrypt(champi->id);
					cds->base_skin.skin = champi->id;
					Update(cds, 1);
				}
			}
			memset(champi, 0, sizeof(champ));
		}
		pipe = connectpipe("\\\\.\\pipe\\skinchangerpipe");
		Sleep(1000);
	}

#ifdef DEBUGSkin
	FreeConsole();
#endif

	CloseHandle(pipe);
	FreeLibraryAndExitThread(mymodule, 0);
	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            DisableThreadLibraryCalls(hModule);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)init, hModule, 0, NULL);
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}