WINBASEAPI DWORD WINAPI GetFileAttributesW(LPCWSTR lpFileName);
WINBASEAPI DWORD WINAPI SetFilePointer(HANDLE hFile, LONG lDistanceToMove,
                                       PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
WINBASEAPI WINBOOL WINAPI
GetFileInformationByHandle(HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation);
WINBASEAPI HANDLE WINAPI CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                     LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                     DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
                                     HANDLE hTemplateFile);
WINBASEAPI HANDLE WINAPI CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                     LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                     DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
                                     HANDLE hTemplateFile);
WINBASEAPI DWORD WINAPI GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
WINBASEAPI LONG WINAPI CompareFileTime(CONST FILETIME *lpFileTime1, CONST FILETIME *lpFileTime2);
WINBASEAPI WINBOOL WINAPI FileTimeToLocalFileTime(CONST FILETIME *lpFileTime,
                                                  LPFILETIME lpLocalFileTime);
WINBASEAPI HANDLE WINAPI FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
WINBASEAPI HANDLE WINAPI FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
WINBASEAPI DWORD WINAPI GetFileAttributesA(LPCSTR lpFileName);
WINBASEAPI WINBOOL WINAPI GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize);
WINBASEAPI WINBOOL WINAPI GetFileTime(HANDLE hFile, LPFILETIME lpCreationTime,
                                      LPFILETIME lpLastAccessTime, LPFILETIME lpLastWriteTime);
WINBASEAPI DWORD WINAPI GetFileType(HANDLE hFile);
WINBASEAPI WINBOOL WINAPI ReadFileScatter(HANDLE hFile, FILE_SEGMENT_ELEMENT aSegmentArray[],
                                          DWORD nNumberOfBytesToRead, LPDWORD lpReserved,
                                          LPOVERLAPPED lpOverlapped);
WINBASEAPI WINBOOL WINAPI SetFileValidData(HANDLE hFile, LONGLONG ValidDataLength);
WINBASEAPI WINBOOL WINAPI WriteFileGather(HANDLE hFile, FILE_SEGMENT_ELEMENT aSegmentArray[],
                                          DWORD nNumberOfBytesToWrite, LPDWORD lpReserved,
                                          LPOVERLAPPED lpOverlapped);
WINBASEAPI UINT WINAPI GetTempFileNameA(LPCSTR lpPathName, LPCSTR lpPrefixString, UINT uUnique,
                                        LPSTR lpTempFileName);
WINBASEAPI UINT WINAPI GetTempFileNameW(LPCWSTR lpPathName, LPCWSTR lpPrefixString, UINT uUnique,
                                        LPWSTR lpTempFileName);
WINBASEAPI WINBOOL WINAPI LocalFileTimeToFileTime(CONST FILETIME *lpLocalFileTime,
                                                  LPFILETIME lpFileTime);
WINBASEAPI WINBOOL WINAPI LockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh,
                                   DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh);
WINBASEAPI WINBOOL WINAPI ReadFileEx(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                                     LPOVERLAPPED lpOverlapped,
                                     LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
WINBASEAPI WINBOOL WINAPI SetFileTime(HANDLE hFile, CONST FILETIME *lpCreationTime,
                                      CONST FILETIME *lpLastAccessTime,
                                      CONST FILETIME *lpLastWriteTime);
WINBASEAPI WINBOOL WINAPI UnlockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh,
                                     DWORD nNumberOfBytesToUnlockLow,
                                     DWORD nNumberOfBytesToUnlockHigh);
WINBASEAPI WINBOOL WINAPI WriteFileEx(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                                      LPOVERLAPPED lpOverlapped,
                                      LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
WINBASEAPI WINBOOL WINAPI DeleteFileA(LPCSTR lpFileName);
WINBASEAPI WINBOOL WINAPI DeleteFileW(LPCWSTR lpFileName);
WINBASEAPI HANDLE WINAPI FindFirstFileExA(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId,
                                          LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp,
                                          LPVOID lpSearchFilter, DWORD dwAdditionalFlags);
WINBASEAPI HANDLE WINAPI FindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId,
                                          LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp,
                                          LPVOID lpSearchFilter, DWORD dwAdditionalFlags);
WINBASEAPI WINBOOL WINAPI FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
WINBASEAPI WINBOOL WINAPI FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
WINBASEAPI WINBOOL WINAPI FlushFileBuffers(HANDLE hFile);
WINBASEAPI WINBOOL WINAPI GetFileAttributesExA(LPCSTR lpFileName,
                                               GET_FILEEX_INFO_LEVELS fInfoLevelId,
                                               LPVOID lpFileInformation);
WINBASEAPI WINBOOL WINAPI GetFileAttributesExW(LPCWSTR lpFileName,
                                               GET_FILEEX_INFO_LEVELS fInfoLevelId,
                                               LPVOID lpFileInformation);
WINBASEAPI WINBOOL WINAPI LockFileEx(HANDLE hFile, DWORD dwFlags, DWORD dwReserved,
                                     DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh,
                                     LPOVERLAPPED lpOverlapped);
WINBASEAPI WINBOOL WINAPI ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                                   LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI WINBOOL WINAPI SetEndOfFile(HANDLE hFile);
WINBASEAPI WINBOOL WINAPI SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes);
WINBASEAPI WINBOOL WINAPI SetFileAttributesW(LPCWSTR lpFileName, DWORD dwFileAttributes);
WINBASEAPI WINBOOL WINAPI SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove,
                                           PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod);
WINBASEAPI WINBOOL WINAPI UnlockFileEx(HANDLE hFile, DWORD dwReserved,
                                       DWORD nNumberOfBytesToUnlockLow,
                                       DWORD nNumberOfBytesToUnlockHigh, LPOVERLAPPED lpOverlapped);
WINBASEAPI WINBOOL WINAPI WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                                    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
WINBASEAPI WINBOOL WINAPI SetFileInformationByHandle(HANDLE hFile,
                                                     FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
                                                     LPVOID lpFileInformation, DWORD dwBufferSize);
WINBASEAPI HANDLE WINAPI CreateFile2(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                     DWORD dwCreationDisposition,
                                     LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams);
DAPI BuildIoRingReadFile(HIORING ioRing, IORING_HANDLE_REF fileRef, IORING_BUFFER_REF dataRef,
                         UINT32 numberOfBytesToRead, UINT64 fileOffset, UINT_PTR userData,
                         IORING_SQE_FLAGS flags);
DAPI BuildIoRingRegisterFileHandles(HIORING ioRing, UINT32 count, HANDLE const handles[],
                                    UINT_PTR userData);
WINBASEAPI WINBOOL WINAPI GetFileMUIInfo(DWORD dwFlags, PCWSTR pcwszFilePath,
                                         PFILEMUIINFO pFileMUIInfo, DWORD *pcbFileMUIInfo);
WINBASEAPI WINBOOL WINAPI GetFileMUIPath(DWORD dwFlags, PCWSTR pcwszFilePath, PWSTR pwszLanguage,
                                         PULONG pcchLanguage, PWSTR pwszFileMUIPath,
                                         PULONG pcchFileMUIPath, PULONGLONG pululEnumerator);
WINBASEAPI VOID WINAPI GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime);
WINBASEAPI VOID WINAPI GetSystemTimePreciseAsFileTime(LPFILETIME lpSystemTimeAsFileTime);
WINBASEAPI WINBOOL WINAPI FlushViewOfFile(LPCVOID lpBaseAddress, SIZE_T dwNumberOfBytesToFlush);
WINBASEAPI WINBOOL WINAPI UnmapViewOfFile(LPCVOID lpBaseAddress);
WINBASEAPI WINBOOL WINAPI UnmapViewOfFile2(HANDLE Process, PVOID BaseAddress, ULONG UnmapFlags);
WINBASEAPI HANDLE WINAPI CreateFileMappingFromApp(HANDLE hFile,
                                                  PSECURITY_ATTRIBUTES SecurityAttributes,
                                                  ULONG PageProtection, ULONG64 MaximumSize,
                                                  PCWSTR Name);
WINBASEAPI PVOID WINAPI MapViewOfFileFromApp(HANDLE hFileMappingObject, ULONG DesiredAccess,
                                             ULONG64 FileOffset, SIZE_T NumberOfBytesToMap);
WINBASEAPI HANDLE WINAPI OpenFileMappingFromApp(ULONG DesiredAccess, WINBOOL InheritHandle,
                                                PCWSTR Name);
WINBASEAPI PVOID WINAPI MapViewOfFile3FromApp(HANDLE FileMapping, HANDLE Process, PVOID BaseAddress,
                                              ULONG64 Offset, SIZE_T ViewSize, ULONG AllocationType,
                                              ULONG PageProtection,
                                              MEM_EXTENDED_PARAMETER *ExtendedParameters,
                                              ULONG ParameterCount);
WINBASEAPI HANDLE WINAPI CreateFileMappingW(HANDLE hFile,
                                            LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
                                            DWORD flProtect, DWORD dwMaximumSizeHigh,
                                            DWORD dwMaximumSizeLow, LPCWSTR lpName);
WINBASEAPI HANDLE WINAPI OpenFileMappingW(DWORD dwDesiredAccess, WINBOOL bInheritHandle,
                                          LPCWSTR lpName);
WINBASEAPI LPVOID WINAPI MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess,
                                       DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow,
                                       SIZE_T dwNumberOfBytesToMap);
WINBASEAPI LPVOID WINAPI MapViewOfFileEx(HANDLE hFileMappingObject, DWORD dwDesiredAccess,
                                         DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow,
                                         SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress);
WINBASEAPI WINBOOL WINAPI GetSystemFileCacheSize(PSIZE_T lpMinimumFileCacheSize,
                                                 PSIZE_T lpMaximumFileCacheSize, PDWORD lpFlags);
WINBASEAPI WINBOOL WINAPI SetSystemFileCacheSize(SIZE_T MinimumFileCacheSize,
                                                 SIZE_T MaximumFileCacheSize, DWORD Flags);
WINBASEAPI HANDLE WINAPI CreateFileMappingNumaW(HANDLE hFile,
                                                LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
                                                DWORD flProtect, DWORD dwMaximumSizeHigh,
                                                DWORD dwMaximumSizeLow, LPCWSTR lpName,
                                                DWORD nndPreferred);
WINBASEAPI PVOID WINAPI MapViewOfFileNuma2(HANDLE FileMappingHandle, HANDLE ProcessHandle,
                                           ULONG64 Offset, PVOID BaseAddress, SIZE_T ViewSize,
                                           ULONG AllocationType, ULONG PageProtection,
                                           ULONG PreferredNode);
WINBASEAPI PVOID WINAPI MapViewOfFile3(HANDLE FileMapping, HANDLE Process, PVOID BaseAddress,
                                       ULONG64 Offset, SIZE_T ViewSize, ULONG AllocationType,
                                       ULONG PageProtection,
                                       MEM_EXTENDED_PARAMETER *ExtendedParameters,
                                       ULONG ParameterCount);
WINBASEAPI HANDLE WINAPI CreateFileMapping2(HANDLE File, SECURITY_ATTRIBUTES *SecurityAttributes,
                                            ULONG DesiredAccess, ULONG PageProtection,
                                            ULONG AllocationAttributes, ULONG64 MaximumSize,
                                            PCWSTR Name, MEM_EXTENDED_PARAMETER *ExtendedParameters,
                                            ULONG ParameterCount);
WINBASEAPI WINBOOL WINAPI UnmapViewOfFileEx(PVOID BaseAddress, ULONG UnmapFlags);
DWORD WINAPI VerFindFileA(DWORD uFlags, LPSTR szFileName, LPSTR szWinDir, LPSTR szAppDir,
                          LPSTR szCurDir, PUINT lpuCurDirLen, LPSTR szDestDir, PUINT lpuDestDirLen);
DWORD WINAPI VerFindFileW(DWORD uFlags, LPWSTR szFileName, LPWSTR szWinDir, LPWSTR szAppDir,
                          LPWSTR szCurDir, PUINT lpuCurDirLen, LPWSTR szDestDir,
                          PUINT lpuDestDirLen);
DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle);
DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle);
DWORD WINAPI GetFileVersionInfoSizeExA(DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle);
DWORD WINAPI GetFileVersionInfoSizeExW(DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle);
WINBOOL WINAPI GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen,
                                   LPVOID lpData);
WINBOOL WINAPI GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen,
                                   LPVOID lpData);
WINBOOL WINAPI GetFileVersionInfoExA(DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle,
                                     DWORD dwLen, LPVOID lpData);
WINBOOL WINAPI GetFileVersionInfoExW(DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle,
                                     DWORD dwLen, LPVOID lpData);
NBASEAPI LONG WINAPI AppPolicyGetCreateFileAccess(HANDLE processToken,
                                                  AppPolicyCreateFileAccess *policy);
WINBASEAPI WINBOOL WINAPI SetFileIoOverlappedRange(HANDLE FileHandle, PUCHAR OverlappedRangeStart,
                                                   ULONG Length);
WINBASEAPI HANDLE WINAPI ReOpenFile(HANDLE hOriginalFile, DWORD dwDesiredAccess, DWORD dwShareMode,
                                    DWORD dwFlagsAndAttributes);
WINBASEAPI DWORD WINAPI GetCompressedFileSizeA(LPCSTR lpFileName, LPDWORD lpFileSizeHigh);
WINBASEAPI DWORD WINAPI GetCompressedFileSizeW(LPCWSTR lpFileName, LPDWORD lpFileSizeHigh);
WINBASEAPI WINBOOL WINAPI CopyFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName,
                                      LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData,
                                      LPBOOL pbCancel, DWORD dwCopyFlags);
WINBASEAPI WINBOOL WINAPI CopyFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName,
                                    WINBOOL bFailIfExists);
WINBASEAPI HRESULT WINAPI CopyFile2(PCWSTR pwszExistingFileName, PCWSTR pwszNewFileName,
                                    COPYFILE2_EXTENDED_PARAMETERS *pExtendedParameters);
WINBASEAPI WINBOOL WINAPI MoveFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName,
                                      DWORD dwFlags);
WINBASEAPI WINBOOL WINAPI MoveFileWithProgressW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName,
                                                LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData,
                                                DWORD dwFlags);
WINBASEAPI WINBOOL WINAPI ReplaceFileW(LPCWSTR lpReplacedFileName, LPCWSTR lpReplacementFileName,
                                       LPCWSTR lpBackupFileName, DWORD dwReplaceFlags,
                                       LPVOID lpExclude, LPVOID lpReserved);
WINBASEAPI HANDLE WINAPI FindFirstFileNameW(LPCWSTR lpFileName, DWORD dwFlags, LPDWORD StringLength,
                                            PWSTR LinkName);
WINBASEAPI WINBOOL APIENTRY FindNextFileNameW(HANDLE hFindStream, LPDWORD StringLength,
                                              PWSTR LinkName);
WINBASEAPI VOID WINAPI SetFileApisToOEM(VOID);
WINBASEAPI VOID WINAPI SetFileApisToANSI(VOID);
WINBASEAPI WINBOOL WINAPI AreFileApisANSI(VOID);
WINBASEAPI LPVOID WINAPI MapViewOfFileExNuma(HANDLE hFileMappingObject, DWORD dwDesiredAccess,
                                             DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow,
                                             SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress,
                                             DWORD nndPreferred);
WINBASEAPI WINBOOL WINAPI
GetFileInformationByHandleEx(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
                             LPVOID lpFileInformation, DWORD dwBufferSize);
WINBASEAPI HANDLE WINAPI OpenFileById(HANDLE hVolumeHint, LPFILE_ID_DESCRIPTOR lpFileId,
                                      DWORD dwDesiredAccess, DWORD dwShareMode,
                                      LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                      DWORD dwFlagsAndAttributes);
WINBASEAPI DWORD WINAPI GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
WINBASEAPI DWORD WINAPI GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
WINPATHCCHAPI HRESULT APIENTRY PathCchRemoveFileSpec(PWSTR pszPath, size_t cchPath);
DWORD WINAPI GetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);
DWORD WINAPI GetModuleFileNameExW(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
DWORD WINAPI GetMappedFileNameW(HANDLE hProcess, LPVOID lpv, LPWSTR lpFilename, DWORD nSize);
DWORD WINAPI GetMappedFileNameA(HANDLE hProcess, LPVOID lpv, LPSTR lpFilename, DWORD nSize);
DWORD WINAPI GetDeviceDriverFileNameA(LPVOID ImageBase, LPSTR lpFilename, DWORD nSize);
DWORD WINAPI GetDeviceDriverFileNameW(LPVOID ImageBase, LPWSTR lpFilename, DWORD nSize);
WINBOOL WINAPI EnumPageFilesW(PENUM_PAGE_FILE_CALLBACKW pCallBackRoutine, LPVOID pContext);
WINBOOL WINAPI EnumPageFilesA(PENUM_PAGE_FILE_CALLBACKA pCallBackRoutine, LPVOID pContext);
DWORD WINAPI GetProcessImageFileNameA(HANDLE hProcess, LPSTR lpImageFileName, DWORD nSize);
DWORD WINAPI GetProcessImageFileNameW(HANDLE hProcess, LPWSTR lpImageFileName, DWORD nSize);
WINBASEAPI WINBOOL WINAPI FileTimeToSystemTime(CONST FILETIME *lpFileTime,
                                               LPSYSTEMTIME lpSystemTime);
WINBASEAPI WINBOOL WINAPI SystemTimeToFileTime(CONST SYSTEMTIME *lpSystemTime,
                                               LPFILETIME lpFileTime);
WINADVAPI WINBOOL WINAPI GetFileSecurityW(LPCWSTR lpFileName,
                                          SECURITY_INFORMATION RequestedInformation,
                                          PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD nLength,
                                          LPDWORD lpnLengthNeeded);
WINADVAPI WINBOOL WINAPI SetFileSecurityW(LPCWSTR lpFileName,
                                          SECURITY_INFORMATION SecurityInformation,
                                          PSECURITY_DESCRIPTOR pSecurityDescriptor);
HRESULT WINAPI WerRegisterFile(PCWSTR pwzFile, WER_REGISTER_FILE_TYPE regFileType, DWORD dwFlags);
HRESULT WINAPI WerUnregisterFile(PCWSTR pwzFilePath);
