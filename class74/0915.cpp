#define BUILD_WINDOWS
#define SECURITY_WIN32
#include <Windows.h>
#include <stdio.h>
#include <security.h>
#include <secext.h>
#include <VersionHelpers.h>
#include <tchar.h>

BOOL success; //to reduce code lines...^^
DWORD errnum; //err num
TCHAR errmsg[256]; //err msg

void NativeSystem(); 
void ComputerName(); 
void ObjectName(); 
void WindowsDirectory(); 
void version1(); 
void version2(DWORD& os_major, DWORD& os_minor, DWORD& service_major, DWORD& service_minor);
void version3();
void ProductInfo(DWORD& os_major, DWORD& os_minor, DWORD& service_major, DWORD& service_minor);

int main()
{
    DWORD os_major = 0, os_minor = 0, service_major = 0, service_minor = 0; // default value is 0.
    NativeSystem();
    ComputerName();
    ObjectName();
    WindowsDirectory();
    version1();
    version2(os_major, os_minor, service_major, service_minor); // to fill in these values
    version3();
    ProductInfo(os_major, os_minor, service_major, service_minor); // use these values.
    return 0;
}


void NativeSystem() {
    printf("--------------------- 1. information by 'GetNativeSystemInfo' ---------------------\n\n\n");
    SYSTEM_INFO si;

    ::GetNativeSystemInfo(&si); // no return value.
    printf("Number of Logical Processors: %d\n", si.dwNumberOfProcessors);
    printf("Page size: %d Bytes\n", si.dwPageSize);
    printf("Processor Mask: 0x%p\n", (PVOID)si.dwActiveProcessorMask);
    printf("Minimum process address: 0x%p\n", si.lpMinimumApplicationAddress);
    printf("Maximum process address: 0x%p\n", si.lpMaximumApplicationAddress);
    return;
}

void ComputerName() {
    printf("\n\n--------------------- 2.information by 'GetComputerName' ---------------------\n\n\n");
    LPWSTR c_name = (LPWSTR)malloc(256); //Unicode. 1 charater -> 2 bytes.
    DWORD c_name_size = 128;  //Using default "W" type function!!!

    success = ::GetComputerNameW(c_name, &c_name_size); //function fail -> return value is 0.
    if (!success) {
        errnum = ::GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errnum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), errmsg, 256, NULL);
        _tprintf(TEXT("GetComputerNameW failed with error %d (%s)"), errnum, errmsg);
    }
    printf("Computer Name: %ls\n", c_name); //print LPWSTR type by %ls
    return;
}

void ObjectName() { //operation fail.
    printf("\n\n--------------------- 3. information by 'GetComputerObjectName' ---------------------\n\n\n");
    LPWSTR o_name = (LPWSTR)malloc(256);
    ULONG o_name_size = 128;
    /*
    success = ::GetComputerObjectNameW(NameDisplay, o_name, &o_name_size); //fail-> return value is 0.
    if (!success) {
        errnum = ::GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errnum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), errmsg, 256, NULL);
        _tprintf(TEXT("GetComputerObjectNameW failed with error %d (%s)"), errnum, errmsg);
    }
    printf("WindowsDirectory Name: %ls\n", o_name);*/

    return;
}

void WindowsDirectory() {
    printf("\n\n--------------------- 4. information by 'GetWindowsDirectory' ---------------------\n\n\n");
    LPWSTR d_name = (LPWSTR)malloc(256);
    UINT d_name_size = 128;
    UINT res;
    res = ::GetWindowsDirectoryW(d_name, d_name_size); //fail->return value is 0. & success -> return value is length.
    if (!res) {
        errnum = ::GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errnum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), errmsg, 256, NULL);
        _tprintf(TEXT("GetWindowsDirectoryW failed with error %d (%s)"), errnum, errmsg);
    }
    else if (d_name_size == res) { //path length is longer than buf size -> return value is buf size 
        printf("path length is more than buffer size..\n");
    }
    printf("WindowsDirectory Name: %ls\n", d_name);
    return;
}

void version1() {
    printf("\n\n--------------------- 5. Windows version by 'GetVersionEx' ---------------------\n\n\n");
    OSVERSIONINFO vi = { sizeof(vi) }; //GetVersionExW cannot read OSVERSIONINFOEXW
    success = ::GetVersionExW(&vi); //fail -> return value is 0.
    if (!success) {
        errnum = ::GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errnum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), errmsg, 256, NULL);
        _tprintf(TEXT("GetVersionExW failed with error %d (%s)"), errnum, errmsg);
    }
    printf("Version : %d.%d.%d\n", vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
    return;
}

void version2(DWORD &os_major, DWORD &os_minor, DWORD &service_major, DWORD &service_minor) {
    printf("\n\n--------------------- 6. Windows version by 'Versionhelpers.h' ---------------------\n\n\n");
    printf("OS Type: ");
    if (IsWindows10OrGreater()){
        printf("Windows10\n");
        os_major = (DWORD)10;
        os_minor = (DWORD)0;
    }
    else if (IsWindows8Point1OrGreater()){
        printf("Windows8\n");
        os_major = (DWORD)6;
        os_minor = (DWORD)3;
    }
    else if (IsWindows8OrGreater()){
        printf("Windows8\n");
        os_major = (DWORD)6;
        os_minor = (DWORD)2;
    }
    else if (IsWindows7SP1OrGreater()){
        printf("Windows7SP1\n");
        os_major = (DWORD)6;
        os_minor = (DWORD)1;
        service_major = (DWORD)1;
    }
    else if (IsWindows7OrGreater()){
        printf("Windows7\n");
        os_major = (DWORD)6;
        os_minor = (DWORD)1;
    }
    else if (IsWindowsVistaSP2OrGreater()){
        printf("VistaSP2\n");
        os_major = (DWORD)6;
        os_minor = (DWORD)0;
        service_major = (DWORD)2;
    }
    else if (IsWindowsVistaSP1OrGreater()){
        printf("VistaSP1r\n");
        os_major = (DWORD)6;
        os_minor = (DWORD)0;
        service_major = (DWORD)1;
    }
    else if (IsWindowsVistaOrGreater()){
        printf("VistaOrGreater\n");
        os_major = (DWORD)6;
        os_minor = (DWORD)0;
    }
    else if (IsWindowsXPSP3OrGreater()){
        printf("XPSP3\n");
        os_major = (DWORD)5;
        os_minor = (DWORD)1;
        service_major = (DWORD)3;
    }

    else if (IsWindowsXPSP2OrGreater()){
        printf("XPSP2\n");
        os_major = (DWORD)5;
        os_minor = (DWORD)1;
        service_major = (DWORD)2;
    }

    else if (IsWindowsXPSP1OrGreater()){
        printf("XPSP1\n");
        os_major = (DWORD)5;
        os_minor = (DWORD)1;
        service_major = (DWORD)1;
    }
    else if (IsWindowsXPOrGreater()){
        printf("XP\n");
        os_major = (DWORD)5;
        os_minor = (DWORD)1;
    }
    else {
        printf("2000\n");
        os_major = (DWORD)5;
        os_minor = (DWORD)0;
    }
    printf("OS version : %d.%d\n",os_major,os_minor);
    printf("Service pack version : %d.%d\n", service_major, service_minor);
    return;
}

void version3() {
    printf("\n\n--------------------- 7. Windows version by 'KUSER_SHARED_DATA struct' ---------------------\n\n\n");
    auto sharedUserData = (BYTE*)0x7FFE0000;

    printf("Version: %d.%d.%d\n",
        *(ULONG*)(sharedUserData + 0x26c), // major version offset
        *(ULONG*)(sharedUserData + 0x270), // minor version offset
        *(ULONG*)(sharedUserData + 0x260)); // build number offset (Windows 10)
    return;
}

void ProductInfo(DWORD& os_major, DWORD& os_minor, DWORD& service_major, DWORD& service_minor) {
    printf("\n\n--------------------- 8. information by 'GetProductInfo' ---------------------\n\n\n");
    DWORD product_type;

    success = ::GetProductInfo(os_major, os_minor, service_major, service_minor, &product_type);
    if (!success) {
        errnum = ::GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errnum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), errmsg, 256, NULL);
        _tprintf(TEXT("GetProductInfo failed with error %d (%s)"), errnum, errmsg);
    }
    printf("product_type: 0x%08x\n", product_type); // find details at https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getproductinfo
    return;
}