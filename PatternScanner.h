DWORD PatternScan(int type, CONST CHAR* szSignature, BOOL bSkipFirst)
{
    static auto patternToByte = [](CONST CHAR* szPattern)
        {
            auto       bytes = std::vector<int>{};
            const auto start = const_cast<char*>(szPattern);
            const auto end = const_cast<char*>(szPattern) + strlen(szPattern);

            for (auto current = start; current < end; ++current)
            {
                if (*current == '?')
                {
                    ++current;
                    if (*current == '?') ++current;
                    bytes.push_back(-1);
                }
                else {
                    bytes.push_back(strtoul(current, &current, 16));
                }
            }

            return bytes;
        };

    if (type == 0)
    {
        DWORD dwCShellEntry = (DWORD)GetModuleHandleA("cshell.dll");

        const auto dosHeader = (PIMAGE_DOS_HEADER)dwCShellEntry;
        const auto ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)dwCShellEntry + dosHeader->e_lfanew);
        const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        auto       patternBytes = patternToByte(szSignature);
        const auto scanBytes = reinterpret_cast<PBYTE>(dwCShellEntry);
        const auto s = patternBytes.size();
        const auto d = patternBytes.data();

        bool bFoundFirst = false;
        for (auto i = 0ul; i < sizeOfImage - s; ++i)
        {
            bool found = true;
            for (auto j = 0ul; j < s; ++j)
            {
                if (scanBytes[i + j] != d[j] && d[j] != -1) { found = false; break; }
            }

            if (found)
            {
                if (bSkipFirst)
                {
                    if (!bFoundFirst) bFoundFirst = true;
                    else
                    {
                        return reinterpret_cast<DWORD>(&scanBytes[i]);
                    }
                }
                else
                {
                    return reinterpret_cast<DWORD>(&scanBytes[i]);
                }
            }
        }
    }
    else if (type == 1)
    {
        DWORD dwEngineEntry = (DWORD)GetModuleHandleA("Engine.exe");

        const auto dosHeader = (PIMAGE_DOS_HEADER)dwEngineEntry;
        const auto ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)dwEngineEntry + dosHeader->e_lfanew);
        const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        auto       patternBytes = patternToByte(szSignature);
        const auto scanBytes = reinterpret_cast<PBYTE>(dwEngineEntry);
        const auto s = patternBytes.size();
        const auto d = patternBytes.data();

        bool bFoundFirst = false;
        for (auto i = 0ul; i < sizeOfImage - s; ++i)
        {
            bool found = true;
            for (auto j = 0ul; j < s; ++j)
            {
                if (scanBytes[i + j] != d[j] && d[j] != -1) { found = false; break; }
            }

            if (found)
            {
                if (bSkipFirst)
                {
                    if (!bFoundFirst) bFoundFirst = true;
                    else
                    {
                        return reinterpret_cast<DWORD>(&scanBytes[i]); 
                    }
                }
                else
                {
                    return reinterpret_cast<DWORD>(&scanBytes[i]);
                }
            }
        }
    }
    else if (type == 2)
    {
        DWORD dwEngine2Entry = (DWORD)GetModuleHandleA("Engine2.exe");

        const auto dosHeader = (PIMAGE_DOS_HEADER)dwEngine2Entry;
        const auto ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)dwEngine2Entry + dosHeader->e_lfanew);
        const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        auto       patternBytes = patternToByte(szSignature);
        const auto scanBytes = reinterpret_cast<PBYTE>(dwEngine2Entry);
        const auto s = patternBytes.size();
        const auto d = patternBytes.data();

        bool bFoundFirst = false;
        for (auto i = 0ul; i < sizeOfImage - s; ++i)
        {
            bool found = true;
            for (auto j = 0ul; j < s; ++j)
            {
                if (scanBytes[i + j] != d[j] && d[j] != -1) { found = false; break; }
            }

            if (found)
            {
                if (bSkipFirst)
                {
                    if (!bFoundFirst) bFoundFirst = true;
                    else
                    {
                        return reinterpret_cast<DWORD>(&scanBytes[i]);
                    }
                }
                else
                {
                    return reinterpret_cast<DWORD>(&scanBytes[i]);
                }
            }
        }
    }

    return 0;
}
DWORD PatternScanAdder(int type, CONST CHAR* szSignature,BOOL Skipper, DWORD Adder)
{
    DWORD pattern = PatternScan(type, szSignature, Skipper);  if (pattern) pattern = *(DWORD*)(pattern + Adder);
    return pattern;
}