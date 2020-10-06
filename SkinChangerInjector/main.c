//author https://github.com/autergame
#define CURL_STATICLIB
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include <tlhelp32.h>
#include <locale.h>
#include <psapi.h>
#include "cJSON.h"
#include "libs/curl.h"
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "crypt32")
#pragma comment(lib, "wldap32")
#pragma comment(lib, "advapi32")
#pragma comment(lib, "normaliz")
#pragma comment(lib, "libs/libcurl")

static int mod_table[] = {
    0, 2, 1
};
static char encoding_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};
char* base64_encode(char* data, int input_length)
{
    int output_length = 4 * ((input_length + 2) / 3);
    char* encoded_data = (char*)calloc(output_length, 1);
    for (int i = 0, j = 0; i < input_length;)
    {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }
    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[output_length - 1 - i] = '=';
    encoded_data[output_length] = '\0';
    return encoded_data;
}
typedef struct url_data
{
    size_t size;
    char* text;
} url_data;
size_t write_data(void* ptr, size_t size, size_t nmemb, url_data* data)
{
    size_t index = data->size;
    size_t n = (size * nmemb);
    data->size += (size * nmemb);
    char* tmp = realloc(data->text, data->size + 1);
    if (tmp)
        data->text = tmp;
    else {
        if (data->text)
            free(data->text);
        fprintf(stderr, "Failed to allocate memory\n");
        return 0;
    }
    memcpy((data->text + index), ptr, n);
    data->text[data->size] = '\0';
    return size * nmemb;
}
char* download_url(char* url, char* port, char* auth, char* protocol)
{
    url_data data;
    data.size = 0;
    data.text = calloc(1, 1);
    curl_global_init(CURL_GLOBAL_ALL);
    CURL* curl = curl_easy_init();
    if (curl)
    {
        char* authfull = calloc(256, 1);
        char* hostfull = calloc(256, 1);
        struct curl_slist* headers = NULL;
        snprintf(hostfull, 256, "https://127.0.0.1:%s%s", port, url);
        curl_easy_setopt(curl, CURLOPT_URL, hostfull);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, protocol);
        headers = curl_slist_append(headers, "Connection: close");
        if (auth != NULL)
        {
            snprintf(authfull, 256, "Authorization: Basic %s", auth);
            headers = curl_slist_append(headers, authfull);
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        free(authfull);
        free(hostfull);
        if (res != CURLE_OK)
            return NULL;
    }
    curl_global_cleanup();
    int nLength = MultiByteToWideChar(CP_UTF8, 0, data.text, strlen(data.text) + 1, NULL, 0);
    wchar_t* bstrWide = SysAllocStringLen(NULL, nLength);
    MultiByteToWideChar(CP_UTF8, 0, data.text, strlen(data.text) + 1, bstrWide, nLength);
    nLength = WideCharToMultiByte(CP_ACP, 0, bstrWide, -1, NULL, 0, NULL, NULL);
    char* pszAnsi = (char*)malloc(nLength);
    WideCharToMultiByte(CP_ACP, 0, bstrWide, -1, pszAnsi, nLength, NULL, NULL);
    SysFreeString(bstrWide);
    free(data.text);
    return pszAnsi;
}

struct nodevoid
{
    void* value;
    uint64_t key;
    struct nodevoid* next;
};
typedef struct HashTableVoid
{
    uint64_t size;
    struct nodevoid** list;
} HashTableVoid;
HashTableVoid* createHashTableVoid(size_t size)
{
    HashTableVoid* t = (HashTableVoid*)malloc(sizeof(HashTableVoid));
    t->size = size;
    t->list = (struct nodevoid**)calloc(size, sizeof(struct nodevoid*));
    return t;
}
void insertHashTableVoid(HashTableVoid* t, uint64_t key, void* val)
{
    uint64_t pos = key % t->size;
    struct nodevoid* list = t->list[pos];
    struct nodevoid* temp = list;
    while (temp) {
        if (temp->key == key) {
            temp->value = val;
            return;
        }
        temp = temp->next;
    }
    struct nodevoid* newNode = (struct nodevoid*)malloc(sizeof(struct nodevoid));
    newNode->key = key;
    newNode->value = val;
    newNode->next = list;
    t->list[pos] = newNode;
}
void* lookupHashTableVoid(HashTableVoid* t, uint64_t key)
{
    struct nodevoid* list = t->list[key % t->size];
    struct nodevoid* temp = list;
    while (temp) {
        if (temp->key == key) {
            return temp->value;
        }
        temp = temp->next;
    }
    return NULL;
}

typedef struct champ
{
    char alias[32];
    uint8_t id;
} champ;
typedef struct nameid
{
    char* name;
    char* alias;
    uint32_t id;
} nameid;
typedef struct skinsid
{
    char* nameone;
    uint8_t nametwo;
} skinsid;
typedef struct skinsname
{
    uint32_t size;
    skinsid** names;
} skinsname;

typedef struct Process
{
    HANDLE handle;
    DWORD processid;
    DWORD baselength;
    DWORD baseaddress;
    char filepath[MAX_PATH];
} Process;
Process* ProcessFind(char* name)
{
    Process* process = (Process*)calloc(1, sizeof(Process));
    PROCESSENTRY32 entry = { .dwSize = sizeof(PROCESSENTRY32) };
    while (1)
    {
        HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (Process32First(handle, &entry))
        {
            do
            {
                if (strcmp(entry.szExeFile, name) == 0)
                {
                    process->handle = OpenProcess(PROCESS_ALL_ACCESS, 0, entry.th32ProcessID);
                    HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, entry.th32ProcessID);
                    MODULEENTRY32 mEntry = { .dwSize = sizeof(MODULEENTRY32) };
                    do {
                        if (strcmp(mEntry.szModule, name) == 0)
                        {
                            process->processid = entry.th32ProcessID;
                            process->baselength = mEntry.modBaseSize;
                            process->baseaddress = (DWORD)mEntry.hModule;
                            K32GetModuleFileNameExA(process->handle, NULL, process->filepath, MAX_PATH);
                            return process;
                        }
                    } while (Module32Next(hmodule, &mEntry));
                }
            } while (Process32Next(handle, &entry));
        }
        Sleep(50);
    }
    return NULL;
}
BOOL isinjected(DWORD pid) 
{
    DWORD cbNeeded;
	HMODULE hMods[1024];
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL)
		return 0;
	if (K32EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) 
	{
		for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) 
		{
			char szModName[MAX_PATH];
			if (K32GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName))) 
			{
				if (strcmp(szModName, "SkinChangerDLL.dll") == 0) 
				{
					CloseHandle(hProcess);
					return 1;
				}
			}
		}
	}
	CloseHandle(hProcess);
	return 0;
}
int injectlegue(char* Param)
{
    Process* process = ProcessFind("League of Legends.exe");
    if (!isinjected(process->processid))
    {
        FILETIME ft;
        SYSTEMTIME st;
        GetSystemTime(&st);
        SystemTimeToFileTime(&st, &ft);

        FILETIME create, exit, kernel, user;
        GetProcessTimes(process->handle, &create, &exit, &kernel, &user);

        int32_t delta = 10 - (int32_t)((*(uint64_t*)(&ft) - *(uint64_t*)(&create.dwLowDateTime)) / 10000000U);
        if (delta > 0)
            Sleep(delta * 1000);

        size_t size = strlen(Param);
        LPVOID dll_path_remote = VirtualAllocEx(process->handle, NULL, size + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!dll_path_remote)
        {
            printf("Failed to alloc space\n");
            CloseHandle(process->handle);
            return 1;
        }

        if (!WriteProcessMemory(process->handle, dll_path_remote, Param, size + 1, NULL))
        {
            printf("Failed to write memory\n");
            VirtualFreeEx(process->handle, dll_path_remote, 0, MEM_RELEASE);
            CloseHandle(process->handle);
            return 1;
        }

        FARPROC loadlib = GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");
        HANDLE thread = CreateRemoteThread(process->handle, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib, dll_path_remote, 0, NULL);
        if (!thread || thread == INVALID_HANDLE_VALUE)
        {
            printf("Failed to create thread\n");
            VirtualFreeEx(process->handle, dll_path_remote, 0, MEM_RELEASE);
            CloseHandle(process->handle);
            return 1;
        }

        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        VirtualFreeEx(process->handle, dll_path_remote, 0, MEM_RELEASE);
        CloseHandle(process->handle);
        return 0;
    }
    return 0;
}

int strcicmp(char* a, char* b)
{
    for (;; a++, b++) {
        int d = tolower(*a) - tolower(*b);
        if (d != 0 || !*a)
            return d;
    }
}

int main(int argc, char** argv)
{
    setlocale(LC_ALL, "");
    HANDLE pipe = CreateNamedPipeA("\\\\.\\pipe\\skinchangerpipe",
        PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, sizeof(champ), sizeof(champ), 2000, NULL);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        printf("Failed to CreateNamedPipe: %d.\n", GetLastError());
        scanf("press enter to exit.");
        return 1;
    }
	char* currentdir = (char*)calloc(256, 1);
	strcat_s(currentdir, 256, argv[0]);
	char* currentdirpos = strrchr(currentdir, '\\');
	currentdir[currentdirpos - currentdir] = '\0';
	strcat_s(currentdir, 256, "\\SkinChangerDLL.dll");
    printf("Waiting league client.\n");
    Process* process = ProcessFind("LeagueClient.exe");
    printf("League client found.\n");
    char* leaguedir = (char*)calloc(256, 1);
    strcat_s(leaguedir, 256, process->filepath);
    char* leaguedirpos = strrchr(leaguedir, '\\');
    leaguedir[leaguedirpos - leaguedir] = '\0';
    for (size_t i = 0; i < strlen(leaguedir); i++)
        if (leaguedir[i] == '\\')
            leaguedir[i] = '/';
    char* lockfiledir = (char*)calloc(256, 1);
    snprintf(lockfiledir, 256, "%s/lockfile", leaguedir);
    FILE* lockfile = fopen(lockfiledir, "rb");
    fseek(lockfile, 0, SEEK_END);
    long fsize = ftell(lockfile);
    while (fsize == 0)
    {
        lockfile = fopen(lockfiledir, "rb");
        fseek(lockfile, 0, SEEK_END);
        fsize = ftell(lockfile);
    }
    fseek(lockfile, 0, SEEK_SET);
    char* lockstr = (char*)malloc(fsize + 1);
    fread(lockstr, fsize, 1, lockfile);
    lockstr[fsize] = '\0';
    fclose(lockfile);
    char* delim = ":";
    strtok(lockstr, delim);
    strtok(NULL, delim);
    char* port = strtok(NULL, delim);
    char* password = strtok(NULL, delim);
    char* protocol = strtok(NULL, delim);
    char* passauth = (char*)calloc(128, 1);
    snprintf(passauth, 128, "riot:%s", password);
    char* auth = base64_encode(passauth, strlen(passauth));

    char* locale = download_url("/riotclient/region-locale", port, auth, protocol);
    cJSON* localejson = cJSON_ParseWithLength(locale, strlen(locale));
    char* region = (char*)cJSON_GetObjectItem(localejson, "locale")->value;

    cJSON* objd;
    char* catalog = download_url("/lol-store/v1/catalog?inventoryType=[\"CHAMPION_SKIN\",\"CHROMA_BUNDLE\"]", port, auth, protocol);
    cJSON* catalogjson = cJSON_ParseWithLength(catalog, strlen(catalog));
    HashTableVoid* hashc = createHashTableVoid(cJSON_GetArraySize(catalogjson));
    for (objd = catalogjson->child; objd != NULL; objd = objd->next)
    {
        uint64_t key = *(uint64_t*)cJSON_GetObjectItem(objd, "itemId")->value;
        cJSON* loca = cJSON_GetObjectItem(cJSON_GetObjectItem(objd, "localizations"), region);
        insertHashTableVoid(hashc, key, cJSON_GetObjectItem(loca, "name")->value);
    }

    int i = 0;
    char* champsummary = download_url("/lol-game-data/assets/v1/champion-summary.json", port, auth, protocol);
    cJSON* jsond = cJSON_ParseWithLength(champsummary, strlen(champsummary));
    size_t sized = cJSON_GetArraySize(jsond) - 1;
    nameid** nameida = (nameid**)malloc(sizeof(nameid*) * sized);
    for (objd = jsond->child; objd != NULL; objd = objd->next)
    {
        nameid* nameide = (nameid*)malloc(sizeof(nameid));
        nameide->id = *(uint32_t*)cJSON_GetObjectItem(objd, "id")->value;
        nameide->name = (char*)cJSON_GetObjectItem(objd, "name")->value;
        nameide->alias = (char*)cJSON_GetObjectItem(objd, "alias")->value;
        nameida[i++] = nameide;
    }

    char* skins = download_url("/lol-game-data/assets/v1/skins.json", port, auth, protocol);
    cJSON* jsone = cJSON_ParseWithLength(skins, strlen(skins));
    skinsname** sknn = (skinsname**)calloc(sized, sizeof(skinsname*));
    for (size_t i = 0; i < sized; i++)
    {
        int ik = 0;
        sknn[i] = (skinsname*)calloc(1, sizeof(skinsname));
        sknn[i]->names = (skinsid**)calloc(1, sizeof(skinsid*));
        for (int k = 1; k < 100; k++)
        {
            char* index = (char*)calloc(16, 1);
            snprintf(index, 16, "%d%03d", nameida[i]->id, k);
            cJSON* var = cJSON_GetObjectItem(jsone, index);
            if (var == NULL)
                continue;
            sknn[i]->size += 1;
            uint32_t ide = *(uint32_t*)cJSON_GetObjectItem(var, "id")->value;
            sknn[i]->names = (skinsid**)realloc(sknn[i]->names, sknn[i]->size * sizeof(skinsid*));
            sknn[i]->names[ik] = (skinsid*)calloc(1, sizeof(skinsid));
            sknn[i]->names[ik]->nameone = cJSON_GetObjectItem(var, "name")->value;
            sknn[i]->names[ik++]->nametwo = ide % 100;
            cJSON* chr = cJSON_GetObjectItem(var, "chromas");
            if (chr != NULL)
            {
                for (objd = chr->child; objd != NULL; objd = objd->next)
                {
                    uint32_t id = *(uint32_t*)cJSON_GetObjectItem(objd, "id")->value;
                    char* name = (char*)lookupHashTableVoid(hashc, id);
                    if (name != NULL)
                    {
                        sknn[i]->size += 1;
                        sknn[i]->names = (skinsid**)realloc(sknn[i]->names, sknn[i]->size * sizeof(skinsid*));
                        sknn[i]->names[ik] = (skinsid*)calloc(1, sizeof(skinsid));
                        sknn[i]->names[ik]->nameone = name;
                        sknn[i]->names[ik++]->nametwo = id % 100;
                    }
                }
            }
        }
    }

    char* Champion = (char*)calloc(32, 1);
    champ* champi = (champ*)calloc(sizeof(champ), 1);
    while (1)
    {
        printf("Type champion name or exit to exit: ");
        scanf("%s", Champion);
        if (strcmp(Champion, "exit") == 0)
            break;

        int choose = -1;
        for (size_t i = 0; i < sized; i++)
        {
            if (strcicmp(Champion, nameida[i]->name) == 0 || strcicmp(Champion, nameida[i]->alias) == 0)
            {
                choose = i;
                break;
            }
        }
        if (choose == -1)
        {
            printf("Champion not found, try again.\n");
            continue;
        }

        for (uint32_t k = 0; k < sknn[choose]->size; k++)
            printf("%d: %s\n", k + 1, sknn[choose]->names[k]->nameone);

        uint8_t num = 0;
        memset(champi, 0, sizeof(champ));
        memcpy(champi->alias, nameida[choose]->alias, strlen(nameida[choose]->alias));
        while (1)
        {
            printf("Type skin number or 0 to exit: ");
            scanf("%hhu", &num);
            if (num == 0)
                break;
            else if (num > sknn[choose]->size)
            {
                printf("Skin number not found, try again.\n");
                continue;
            }

            champi->id = sknn[choose]->names[num-1]->nametwo;
            printf("Waiting league of legends.\n");
            while (1)
            {
                char* stats = download_url("/liveclientdata/gamestats", "2999", NULL, "https");
                if (stats != NULL)
                {
                    cJSON* jsonk = cJSON_ParseWithLength(stats, strlen(stats));
                    cJSON* var = cJSON_GetObjectItem(jsonk, "gameTime");
                    if (var != NULL)
                    {
                        float time = *(float*)var->value;
                        if (time > 10.f)
                            break;
                    }
                }
                Sleep(1000);
            }
            if (injectlegue(currentdir) == 1)
            {
                scanf("press enter to exit.");
                CloseHandle(pipe);
                return 1;
            }
            while (ConnectNamedPipe(pipe, NULL) == FALSE)
            {
                Sleep(1000);
            }

            BOOL result = WriteFile(pipe, champi, sizeof(champ), NULL, NULL);
            if (!result)
            {
                printf("Failed to send data: %d.\n", GetLastError());
                scanf("press enter to exit.");
                CloseHandle(pipe);
                return 1;
            }

            FlushFileBuffers(pipe);
            if (!DisconnectNamedPipe(pipe))
            {
                printf("Disconnect failed %d\n", GetLastError());
                scanf("press enter to exit.");
                CloseHandle(pipe);
                return 1;
            }
        }
    }
	return 0;
}