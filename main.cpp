#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <shlwapi.h>
#include <tchar.h>

#include <vector>
#include <string>
#include <algorithm>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "shlwapi.lib")

// --- Структуры данных ---
struct ProcessInfo {
    DWORD pid;
    std::string name;
    std::string riskLevel;
    std::string notes;
    int threatScore;
};

// --- Глобальные переменные ---
std::vector<ProcessInfo> foundProcesses;
ID3D11Device* g_pd3dDevice = nullptr;
ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
IDXGISwapChain* g_pSwapChain = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

// --- Вспомогательные функции анализа ---

const std::vector<std::string> whitelist = {
    "xraycore.exe"
};

std::string GetProcessPath(DWORD pid) {
    TCHAR szPath[MAX_PATH];
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        DWORD dwSize = MAX_PATH;
        if (QueryFullProcessImageName(hProcess, 0, szPath, &dwSize)) {
            CloseHandle(hProcess);
#ifdef UNICODE
            std::wstring ws(szPath);
            return std::string(ws.begin(), ws.end());
#else
            return std::string(szPath);
#endif
        }
        CloseHandle(hProcess);
    }
    return "Unknown";
}

std::string GetProcessNameById(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return "Unknown";
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                CloseHandle(hSnapshot);
#ifdef UNICODE
                std::wstring ws(pe32.szExeFile);
                return std::string(ws.begin(), ws.end());
#else
                return std::string(pe32.szExeFile);
#endif
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return "Unknown";
}

void DeepScan() {
    foundProcesses.clear();
    PMIB_TCPTABLE_OWNER_PID pTcpTable;
    DWORD dwSize = 0;

    GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);


    if (GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            if (pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
                DWORD pid = pTcpTable->table[i].dwOwningPid;
                int port = ntohs((u_short)pTcpTable->table[i].dwRemotePort);

                std::string procName = GetProcessNameById(pid);
                std::string fullPath = GetProcessPath(pid);
                std::string lowName = procName;
                std::transform(lowName.begin(), lowName.end(), lowName.begin(), ::tolower);

                ProcessInfo info = { pid, procName, "Safe", "", 0 };

                bool isWhitelisted = false;
                for (const auto& okProc : whitelist) {
                    if (_stricmp(procName.c_str(), okProc.c_str()) == 0) {
                        isWhitelisted = true;
                        break;
                    }
                }

                if (isWhitelisted) {
                    info.riskLevel = "Safe";
                    info.threatScore = 0;
                    info.notes = "Trusted Application (Whitelisted)";
                }
                else {

                    // --- ЭВРИСТИЧЕСКИЙ ДВИЖОК ---
                    if (fullPath.find("\\Temp\\") != std::string::npos || fullPath.find("\\AppData\\Local\\") != std::string::npos) {
                        info.threatScore += 45;
                        info.notes += "[PATH] Unverified location. ";
                    }

                    std::vector<std::string> triggers = { "hack", "chiti", "cheat", "stealer", "grabber", "inject", "rat" };
                    for (const auto& t : triggers) {
                        if (lowName.find(t) != std::string::npos) {
                            info.threatScore += 40;
                            info.notes += "[NAME] Suspicious pattern. ";
                            break;
                        }
                    }

                    if (port > 1024 && port != 80 && port != 443 && port != 8080) {
                        info.threatScore += 20;
                        info.notes += "[NET] High-range port. ";
                    }
                }

                if (info.threatScore >= 60) info.riskLevel = "Malicious";
                else if (info.threatScore >= 30) info.riskLevel = "Suspicious";
                else info.riskLevel = "Safe";

                bool isSystem = (lowName == "svchost.exe" || lowName == "lsass.exe" || lowName == "system");
                if (!isSystem || info.threatScore > 0) {
                    foundProcesses.push_back(info);
                }
            }
        }
    }
    free(pTcpTable);
}

// --- Рендеринг интерфейса ---

void ShowResultWindow() {
    ImGui::SetNextWindowSize(ImVec2(800, 450), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("HEURISTIC ANALYSIS REPORT", nullptr)) {
        if (ImGui::BeginTable("Results", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 50.0f);
            ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Score", ImGuiTableColumnFlags_WidthFixed, 50.0f);
            ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableSetupColumn("Detections", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (const auto& proc : foundProcesses) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::Text("%d", proc.pid);
                ImGui::TableSetColumnIndex(1); ImGui::Text("%s", proc.name.c_str());
                ImGui::TableSetColumnIndex(2); ImGui::Text("%d", proc.threatScore);
                ImGui::TableSetColumnIndex(3);
                if (proc.riskLevel == "Malicious") ImGui::TextColored(ImVec4(1, 0.2f, 0.2f, 1), "MALICIOUS");
                else if (proc.riskLevel == "Suspicious") ImGui::TextColored(ImVec4(1, 0.8f, 0, 1), "SUSPICIOUS");
                else ImGui::TextColored(ImVec4(0.2f, 1, 0.2f, 1), "SAFE");
                ImGui::TableSetColumnIndex(4); ImGui::TextWrapped("%s", proc.notes.c_str());
            }
            ImGui::EndTable();
        }
    }
    ImGui::End();
}

void RenderUI() {
    ImGui::SetNextWindowSize(ImVec2(400, 250), ImGuiCond_Always);
    ImGui::Begin("GREYCE ENGINE v3.2", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.8f, 1.0f, 1.0f));
    ImGui::Text("SYSTEM STATUS: ACTIVE");
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();

    if (ImGui::Button("DEEP BEHAVIORAL SCAN", ImVec2(-1, 60))) {
        DeepScan();
    }

    ImGui::Spacing();
    ImGui::TextDisabled("Analyzed objects: %d", (int)foundProcesses.size());
    ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 30);
    ImGui::TextDisabled("Powered by GreyceSec 2026");
    ImGui::End();

    if (!foundProcesses.empty()) ShowResultWindow();
}

// --- DirectX 11 & Win32 Boilerplate ---

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, hInstance, NULL, NULL, NULL, NULL, _T("GreyceEngine"), NULL };
    ::RegisterClassEx(&wc);
    HWND hwnd = ::CreateWindow(wc.lpszClassName, _T("Greyce Engine v3.2"), WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, NULL, NULL, wc.hInstance, NULL);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ::ShowWindow(hwnd, nCmdShow);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;

    // Стиль
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 8.0f;
    style.FrameRounding = 4.0f;
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.06f, 0.08f, 0.94f);

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    MSG msg;
    while (::GetMessage(&msg, NULL, 0, 0)) {
        ::TranslateMessage(&msg);
        ::DispatchMessage(&msg);
        if (msg.message == WM_QUIT) break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        RenderUI();

        ImGui::Render();
        const float clear_color_with_alpha[4] = { 0.05f, 0.05f, 0.05f, 1.00f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}

bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelsRequested[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelsRequested, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
        return false;
    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProc(hWnd, msg, wParam, lParam);
}