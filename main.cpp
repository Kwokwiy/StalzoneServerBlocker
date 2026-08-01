#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include <commctrl.h>
#include <dwmapi.h>
#include <iphlpapi.h>
#include <netfw.h>
#include <shellapi.h>
#include <uxtheme.h>

#include "resource.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace
{
    constexpr wchar_t WINDOW_CLASS_NAME[] =
        L"StalzoneServerBlockerWindowClass";

    constexpr wchar_t ALL_OUTBOUND_RULE_NAME[] =
        L"STALZONE Server Blocker - ALL Outbound";

    constexpr wchar_t ALL_INBOUND_RULE_NAME[] =
        L"STALZONE Server Blocker - ALL Inbound";

    // Kept only so an upgrade removes rules created by older versions.
    constexpr wchar_t LEGACY_UDP_RULE_NAME[] =
        L"STALZONE Server Blocker - UDP";

    constexpr wchar_t LEGACY_TCP_RULE_NAME[] =
        L"STALZONE Server Blocker - TCP";

    constexpr wchar_t LEGACY_UDP_INBOUND_RULE_NAME[] =
        L"STALZONE Server Blocker - UDP Inbound";

    constexpr wchar_t LEGACY_TCP_INBOUND_RULE_NAME[] =
        L"STALZONE Server Blocker - TCP Inbound";

    constexpr wchar_t FIREWALL_GROUP_NAME[] =
        L"STALZONE Server Blocker";

    constexpr wchar_t SETTINGS_REGISTRY_PATH[] =
        L"Software\\Kwokwiy\\StalzoneServerBlocker";

    constexpr wchar_t WHITE_THEME_SETTING_NAME[] =
        L"WhiteTheme";

    constexpr wchar_t ACCENT_THEME_SETTING_NAME[] =
        L"AccentTheme";

    constexpr int ID_SERVER_TREE = 1000;
    constexpr int ID_BLOCK_SELECTED = 1001;
    constexpr int ID_REMOVE_BLOCKS = 1002;
    constexpr int ID_TOGGLE_WHITE_THEME = 1003;
    constexpr int ID_ACCENT_COLOR = 1004;
    constexpr int ID_ACCENT_RED = 1100;
    constexpr int ID_ACCENT_GREEN = 1101;
    constexpr int ID_ACCENT_ORANGE = 1102;
    constexpr int ID_ACCENT_PURPLE = 1103;
    constexpr int ID_ACCENT_PINK = 1104;
    constexpr int ID_ACCENT_BLUE = 1105;

    COLORREF WINDOW_BACKGROUND = RGB(0, 0, 0);
    COLORREF WINDOW_TEXT = RGB(235, 235, 235);
    COLORREF MUTED_TEXT = RGB(174, 42, 42);
    COLORREF ACCENT_RED = RGB(220, 20, 45);
    COLORREF ACCENT_RED_DARK = RGB(72, 5, 12);
    COLORREF ACCENT_RED_HOVER = RGB(130, 8, 20);
    COLORREF CONTROL_BORDER = RGB(115, 10, 20);
    constexpr DWORD DWM_BORDER_COLOR_ATTRIBUTE = 34;
    constexpr DWORD DWM_CAPTION_COLOR_ATTRIBUTE = 35;
    constexpr DWORD DWM_TEXT_COLOR_ATTRIBUTE = 36;
    constexpr COLORREF NO_WINDOW_BORDER_COLOR =
        0xFFFFFFFE;

    enum class AccentTheme
    {
        Red,
        Green,
        Orange,
        Purple,
        Pink,
        Blue
    };

    struct ServerEntry
    {
        std::string name;
        std::string address;
        std::string ip;
        std::uint16_t port = 0;
        bool selected = false;
    };

    struct ServerPool
    {
        std::string name;
        std::string region;
        std::vector<ServerEntry> servers;
    };

    struct TreeNodeData
    {
        std::size_t poolIndex = 0;
        std::size_t serverIndex = 0;
        bool isPool = false;
    };

    HWND g_mainWindow = nullptr;
    HWND g_headerLabel = nullptr;
    HWND g_authorLabel = nullptr;
    HWND g_serverTree = nullptr;
    HWND g_blockButton = nullptr;
    HWND g_removeButton = nullptr;
    HWND g_themeButton = nullptr;
    HWND g_colorButton = nullptr;
    HWND g_statusLabel = nullptr;

    HFONT g_interfaceFont = nullptr;
    HFONT g_groupFont = nullptr;
    HFONT g_buttonFont = nullptr;
    HBRUSH g_backgroundBrush = nullptr;
    HIMAGELIST g_treeStateImages = nullptr;
    HICON g_largeExternalIcon = nullptr;
    HICON g_smallExternalIcon = nullptr;
    bool g_orbitronLoaded = false;

    std::vector<ServerPool> g_serverPools;
    std::vector<std::filesystem::path> g_loadedFontFiles;
    std::vector<HANDLE> g_loadedMemoryFonts;
    std::vector<std::unique_ptr<TreeNodeData>> g_treeNodes;
    std::vector<HTREEITEM> g_poolTreeItems;
    std::vector<std::vector<HTREEITEM>> g_serverTreeItems;
    bool g_firewallRulesActive = false;
    bool g_whiteTheme = false;
    AccentTheme g_accentTheme = AccentTheme::Red;
    std::wstring g_initialStatus;
    std::wstring g_firewallOperationStage;

    void LoadAppearanceSettings()
    {
        DWORD valueType = 0;
        DWORD valueSize = sizeof(DWORD);
        DWORD whiteThemeValue = 0;

        if (
            RegGetValueW(
                HKEY_CURRENT_USER,
                SETTINGS_REGISTRY_PATH,
                WHITE_THEME_SETTING_NAME,
                RRF_RT_REG_DWORD,
                &valueType,
                &whiteThemeValue,
                &valueSize
            ) ==
            ERROR_SUCCESS
        )
        {
            g_whiteTheme =
                whiteThemeValue != 0;
        }

        valueType = 0;
        valueSize = sizeof(DWORD);
        DWORD accentThemeValue = 0;

        if (
            RegGetValueW(
                HKEY_CURRENT_USER,
                SETTINGS_REGISTRY_PATH,
                ACCENT_THEME_SETTING_NAME,
                RRF_RT_REG_DWORD,
                &valueType,
                &accentThemeValue,
                &valueSize
            ) ==
                ERROR_SUCCESS &&
            accentThemeValue <=
                static_cast<DWORD>(
                    AccentTheme::Blue
                )
        )
        {
            g_accentTheme =
                static_cast<AccentTheme>(
                    accentThemeValue
                );
        }
    }

    void SaveAppearanceSettings()
    {
        HKEY settingsKey = nullptr;

        if (
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                SETTINGS_REGISTRY_PATH,
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                nullptr,
                &settingsKey,
                nullptr
            ) !=
            ERROR_SUCCESS
        )
        {
            return;
        }

        const DWORD whiteThemeValue =
            g_whiteTheme ? 1 : 0;

        const DWORD accentThemeValue =
            static_cast<DWORD>(
                g_accentTheme
            );

        RegSetValueExW(
            settingsKey,
            WHITE_THEME_SETTING_NAME,
            0,
            REG_DWORD,
            reinterpret_cast<const BYTE*>(
                &whiteThemeValue
            ),
            sizeof(whiteThemeValue)
        );

        RegSetValueExW(
            settingsKey,
            ACCENT_THEME_SETTING_NAME,
            0,
            REG_DWORD,
            reinterpret_cast<const BYTE*>(
                &accentThemeValue
            ),
            sizeof(accentThemeValue)
        );

        RegCloseKey(settingsKey);
    }

    COLORREF BlendColors(
        COLORREF foreground,
        COLORREF background,
        int foregroundPercent)
    {
        const int backgroundPercent =
            100 - foregroundPercent;

        const auto blendChannel =
            [foregroundPercent, backgroundPercent](
                BYTE foregroundChannel,
                BYTE backgroundChannel)
            {
                return static_cast<BYTE>(
                    (
                        foregroundChannel *
                            foregroundPercent +
                        backgroundChannel *
                            backgroundPercent
                    ) /
                    100
                );
            };

        return RGB(
            blendChannel(
                GetRValue(foreground),
                GetRValue(background)
            ),
            blendChannel(
                GetGValue(foreground),
                GetGValue(background)
            ),
            blendChannel(
                GetBValue(foreground),
                GetBValue(background)
            )
        );
    }

    COLORREF GetAccentColor(AccentTheme theme)
    {
        switch (theme)
        {
            case AccentTheme::Green:
                return RGB(32, 200, 96);

            case AccentTheme::Orange:
                return RGB(255, 126, 28);

            case AccentTheme::Purple:
                return RGB(153, 72, 255);

            case AccentTheme::Pink:
                return RGB(255, 74, 161);

            case AccentTheme::Blue:
                return RGB(38, 190, 255);

            case AccentTheme::Red:
            default:
                return RGB(220, 20, 45);
        }
    }

    const wchar_t* GetAccentName(AccentTheme theme)
    {
        switch (theme)
        {
            case AccentTheme::Green:
                return L"GREEN";

            case AccentTheme::Orange:
                return L"ORANGE";

            case AccentTheme::Purple:
                return L"PURPLE";

            case AccentTheme::Pink:
                return L"PINK";

            case AccentTheme::Blue:
                return L"SKY BLUE";

            case AccentTheme::Red:
            default:
                return L"RED";
        }
    }

    COLORREF GetContrastingTextColor(COLORREF background)
    {
        const int luminance =
            (
                static_cast<int>(GetRValue(background)) *
                    299 +
                static_cast<int>(GetGValue(background)) *
                    587 +
                static_cast<int>(GetBValue(background)) *
                    114
            ) /
            1000;

        return luminance >= 150
            ? RGB(0, 0, 0)
            : RGB(255, 255, 255);
    }

    void RefreshThemePalette()
    {
        WINDOW_BACKGROUND = g_whiteTheme
            ? RGB(250, 250, 250)
            : RGB(0, 0, 0);

        WINDOW_TEXT = g_whiteTheme
            ? RGB(24, 24, 24)
            : RGB(235, 235, 235);

        ACCENT_RED = GetAccentColor(g_accentTheme);

        ACCENT_RED_DARK = BlendColors(
            ACCENT_RED,
            WINDOW_BACKGROUND,
            g_whiteTheme ? 20 : 32
        );

        ACCENT_RED_HOVER = BlendColors(
            ACCENT_RED,
            WINDOW_BACKGROUND,
            g_whiteTheme ? 70 : 58
        );

        CONTROL_BORDER = BlendColors(
            ACCENT_RED,
            WINDOW_BACKGROUND,
            g_whiteTheme ? 75 : 55
        );

        MUTED_TEXT = BlendColors(
            ACCENT_RED,
            WINDOW_BACKGROUND,
            g_whiteTheme ? 50 : 70
        );
    }

    void ApplyWindowChromeTheme()
    {
        if (!g_mainWindow)
        {
            return;
        }

        BOOL useDarkTitleBar =
            g_whiteTheme ? FALSE : TRUE;

        DwmSetWindowAttribute(
            g_mainWindow,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &useDarkTitleBar,
            sizeof(useDarkTitleBar)
        );

        const COLORREF titleBarColor =
            WINDOW_BACKGROUND;

        const COLORREF titleTextColor =
            ACCENT_RED;

        const COLORREF windowBorderColor =
            NO_WINDOW_BORDER_COLOR;

        DwmSetWindowAttribute(
            g_mainWindow,
            DWM_CAPTION_COLOR_ATTRIBUTE,
            &titleBarColor,
            sizeof(titleBarColor)
        );

        DwmSetWindowAttribute(
            g_mainWindow,
            DWM_TEXT_COLOR_ATTRIBUTE,
            &titleTextColor,
            sizeof(titleTextColor)
        );

        DwmSetWindowAttribute(
            g_mainWindow,
            DWM_BORDER_COLOR_ATTRIBUTE,
            &windowBorderColor,
            sizeof(windowBorderColor)
        );
    }

    void UpdateCustomizationButtonText()
    {
        if (g_themeButton)
        {
            SetWindowTextW(
                g_themeButton,
                g_whiteTheme
                    ? L"WHITE THEME: ON"
                    : L"WHITE THEME: OFF"
            );
        }

        if (g_colorButton)
        {
            const std::wstring text =
                std::wstring(L"COLOR: ") +
                GetAccentName(g_accentTheme);

            SetWindowTextW(
                g_colorButton,
                text.c_str()
            );
        }
    }

    std::wstring Utf8ToWide(std::string_view text)
    {
        if (text.empty())
        {
            return {};
        }

        const int requiredLength = MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            nullptr,
            0
        );

        if (requiredLength <= 0)
        {
            return std::wstring(text.begin(), text.end());
        }

        std::wstring result(
            static_cast<std::size_t>(requiredLength),
            L'\0'
        );

        MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            result.data(),
            requiredLength
        );

        return result;
    }

    std::string WideToUtf8(std::wstring_view text)
    {
        if (text.empty())
        {
            return {};
        }

        const int requiredLength = WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            nullptr,
            0,
            nullptr,
            nullptr
        );

        if (requiredLength <= 0)
        {
            return {};
        }

        std::string result(
            static_cast<std::size_t>(requiredLength),
            '\0'
        );

        WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            result.data(),
            requiredLength,
            nullptr,
            nullptr
        );

        return result;
    }

    class ServersJsonParser
    {
    public:
        explicit ServersJsonParser(std::string_view source)
            : source_(source)
        {
        }

        bool Parse(std::vector<ServerPool>& pools)
        {
            pools.clear();
            SkipWhitespace();

            if (!Expect('{'))
            {
                return false;
            }

            bool poolsFound = false;
            SkipWhitespace();

            if (Consume('}'))
            {
                return Fail("The root JSON object is empty");
            }

            while (true)
            {
                std::string key;

                if (!ParseString(key) || !Expect(':'))
                {
                    return false;
                }

                if (key == "pools")
                {
                    if (poolsFound)
                    {
                        return Fail("The pools property is duplicated");
                    }

                    if (!ParsePools(pools))
                    {
                        return false;
                    }

                    poolsFound = true;
                }
                else if (!SkipValue())
                {
                    return false;
                }

                SkipWhitespace();

                if (Consume('}'))
                {
                    break;
                }

                if (!Expect(','))
                {
                    return false;
                }
            }

            SkipWhitespace();

            if (position_ != source_.size())
            {
                return Fail("Unexpected data after the root JSON object");
            }

            if (!poolsFound)
            {
                return Fail("The pools property was not found");
            }

            if (pools.empty())
            {
                return Fail("The pools array is empty");
            }

            return true;
        }

        const std::string& Error() const
        {
            return error_;
        }

    private:
        void SkipWhitespace()
        {
            while (
                position_ < source_.size() &&
                std::isspace(
                    static_cast<unsigned char>(source_[position_])
                )
            )
            {
                ++position_;
            }
        }

        bool Consume(char expected)
        {
            SkipWhitespace();

            if (
                position_ < source_.size() &&
                source_[position_] == expected
            )
            {
                ++position_;
                return true;
            }

            return false;
        }

        bool Expect(char expected)
        {
            if (Consume(expected))
            {
                return true;
            }

            std::string message = "Expected '";
            message.push_back(expected);
            message.push_back('\'');
            return Fail(message);
        }

        bool ParseString(std::string& output)
        {
            output.clear();
            SkipWhitespace();

            if (
                position_ >= source_.size() ||
                source_[position_] != '"'
            )
            {
                return Fail("Expected a JSON string");
            }

            ++position_;

            while (position_ < source_.size())
            {
                const char current = source_[position_++];

                if (current == '"')
                {
                    return true;
                }

                if (
                    static_cast<unsigned char>(current) < 0x20
                )
                {
                    return Fail("A JSON string contains a control character");
                }

                if (current != '\\')
                {
                    output.push_back(current);
                    continue;
                }

                if (position_ >= source_.size())
                {
                    return Fail("An escape sequence is incomplete");
                }

                const char escaped = source_[position_++];

                switch (escaped)
                {
                    case '"':
                    case '\\':
                    case '/':
                        output.push_back(escaped);
                        break;

                    case 'b':
                        output.push_back('\b');
                        break;

                    case 'f':
                        output.push_back('\f');
                        break;

                    case 'n':
                        output.push_back('\n');
                        break;

                    case 'r':
                        output.push_back('\r');
                        break;

                    case 't':
                        output.push_back('\t');
                        break;

                    case 'u':
                    {
                        std::uint32_t codePoint = 0;

                        if (!ParseHexCodeUnit(codePoint))
                        {
                            return false;
                        }

                        if (
                            codePoint >= 0xD800 &&
                            codePoint <= 0xDBFF
                        )
                        {
                            if (
                                position_ + 2 > source_.size() ||
                                source_[position_] != '\\' ||
                                source_[position_ + 1] != 'u'
                            )
                            {
                                return Fail("A Unicode surrogate pair is incomplete");
                            }

                            position_ += 2;
                            std::uint32_t lowSurrogate = 0;

                            if (!ParseHexCodeUnit(lowSurrogate))
                            {
                                return false;
                            }

                            if (
                                lowSurrogate < 0xDC00 ||
                                lowSurrogate > 0xDFFF
                            )
                            {
                                return Fail("A Unicode surrogate pair is invalid");
                            }

                            codePoint =
                                0x10000 +
                                ((codePoint - 0xD800) << 10) +
                                (lowSurrogate - 0xDC00);
                        }
                        else if (
                            codePoint >= 0xDC00 &&
                            codePoint <= 0xDFFF
                        )
                        {
                            return Fail("An unexpected low Unicode surrogate was found");
                        }

                        AppendUtf8(output, codePoint);
                        break;
                    }

                    default:
                        return Fail("An unsupported escape sequence was found");
                }
            }

            return Fail("A JSON string is not terminated");
        }

        bool ParseHexCodeUnit(std::uint32_t& value)
        {
            if (position_ + 4 > source_.size())
            {
                return Fail("A Unicode escape sequence is incomplete");
            }

            value = 0;

            for (int index = 0; index < 4; ++index)
            {
                const char character = source_[position_++];
                value <<= 4;

                if (character >= '0' && character <= '9')
                {
                    value += static_cast<std::uint32_t>(
                        character - '0'
                    );
                }
                else if (
                    character >= 'a' &&
                    character <= 'f'
                )
                {
                    value += static_cast<std::uint32_t>(
                        character - 'a' + 10
                    );
                }
                else if (
                    character >= 'A' &&
                    character <= 'F'
                )
                {
                    value += static_cast<std::uint32_t>(
                        character - 'A' + 10
                    );
                }
                else
                {
                    return Fail("A Unicode escape sequence is invalid");
                }
            }

            return true;
        }

        static void AppendUtf8(
            std::string& output,
            std::uint32_t codePoint)
        {
            if (codePoint <= 0x7F)
            {
                output.push_back(static_cast<char>(codePoint));
            }
            else if (codePoint <= 0x7FF)
            {
                output.push_back(
                    static_cast<char>(
                        0xC0 | (codePoint >> 6)
                    )
                );

                output.push_back(
                    static_cast<char>(
                        0x80 | (codePoint & 0x3F)
                    )
                );
            }
            else if (codePoint <= 0xFFFF)
            {
                output.push_back(
                    static_cast<char>(
                        0xE0 | (codePoint >> 12)
                    )
                );

                output.push_back(
                    static_cast<char>(
                        0x80 | ((codePoint >> 6) & 0x3F)
                    )
                );

                output.push_back(
                    static_cast<char>(
                        0x80 | (codePoint & 0x3F)
                    )
                );
            }
            else
            {
                output.push_back(
                    static_cast<char>(
                        0xF0 | (codePoint >> 18)
                    )
                );

                output.push_back(
                    static_cast<char>(
                        0x80 | ((codePoint >> 12) & 0x3F)
                    )
                );

                output.push_back(
                    static_cast<char>(
                        0x80 | ((codePoint >> 6) & 0x3F)
                    )
                );

                output.push_back(
                    static_cast<char>(
                        0x80 | (codePoint & 0x3F)
                    )
                );
            }
        }

        bool ParsePools(std::vector<ServerPool>& pools)
        {
            if (!Expect('['))
            {
                return false;
            }

            SkipWhitespace();

            if (Consume(']'))
            {
                return true;
            }

            while (true)
            {
                ServerPool pool;

                if (!ParsePool(pool))
                {
                    return false;
                }

                pools.push_back(std::move(pool));
                SkipWhitespace();

                if (Consume(']'))
                {
                    break;
                }

                if (!Expect(','))
                {
                    return false;
                }
            }

            return true;
        }

        bool ParsePool(ServerPool& pool)
        {
            if (!Expect('{'))
            {
                return false;
            }

            bool nameFound = false;
            bool tunnelsFound = false;
            SkipWhitespace();

            if (Consume('}'))
            {
                return Fail("A pool object is empty");
            }

            while (true)
            {
                std::string key;

                if (!ParseString(key) || !Expect(':'))
                {
                    return false;
                }

                if (key == "name")
                {
                    if (!ParseString(pool.name))
                    {
                        return false;
                    }

                    nameFound = true;
                }
                else if (key == "region")
                {
                    if (!ParseString(pool.region))
                    {
                        return false;
                    }
                }
                else if (key == "tunnels")
                {
                    if (!ParseServers(pool.servers))
                    {
                        return false;
                    }

                    tunnelsFound = true;
                }
                else if (!SkipValue())
                {
                    return false;
                }

                SkipWhitespace();

                if (Consume('}'))
                {
                    break;
                }

                if (!Expect(','))
                {
                    return false;
                }
            }

            if (!nameFound || pool.name.empty())
            {
                return Fail("A pool does not have a valid name");
            }

            if (!tunnelsFound)
            {
                return Fail("A pool does not have a tunnels array");
            }

            return true;
        }

        bool ParseServers(std::vector<ServerEntry>& servers)
        {
            if (!Expect('['))
            {
                return false;
            }

            SkipWhitespace();

            if (Consume(']'))
            {
                return true;
            }

            while (true)
            {
                ServerEntry server;

                if (!ParseServer(server))
                {
                    return false;
                }

                servers.push_back(std::move(server));
                SkipWhitespace();

                if (Consume(']'))
                {
                    break;
                }

                if (!Expect(','))
                {
                    return false;
                }
            }

            return true;
        }

        bool ParseServer(ServerEntry& server)
        {
            if (!Expect('{'))
            {
                return false;
            }

            bool nameFound = false;
            bool addressFound = false;
            SkipWhitespace();

            if (Consume('}'))
            {
                return Fail("A server object is empty");
            }

            while (true)
            {
                std::string key;

                if (!ParseString(key) || !Expect(':'))
                {
                    return false;
                }

                if (key == "name")
                {
                    if (!ParseString(server.name))
                    {
                        return false;
                    }

                    nameFound = true;
                }
                else if (key == "address")
                {
                    if (!ParseString(server.address))
                    {
                        return false;
                    }

                    addressFound = true;
                }
                else if (!SkipValue())
                {
                    return false;
                }

                SkipWhitespace();

                if (Consume('}'))
                {
                    break;
                }

                if (!Expect(','))
                {
                    return false;
                }
            }

            if (!nameFound || server.name.empty())
            {
                return Fail("A server does not have a valid name");
            }

            if (!addressFound || server.address.empty())
            {
                return Fail("A server does not have a valid address");
            }

            return true;
        }

        bool SkipValue()
        {
            SkipWhitespace();

            if (position_ >= source_.size())
            {
                return Fail("A JSON value is missing");
            }

            switch (source_[position_])
            {
                case '"':
                {
                    std::string ignored;
                    return ParseString(ignored);
                }

                case '{':
                    return SkipObject();

                case '[':
                    return SkipArray();

                case 't':
                    return SkipLiteral("true");

                case 'f':
                    return SkipLiteral("false");

                case 'n':
                    return SkipLiteral("null");

                default:
                    return SkipNumber();
            }
        }

        bool SkipObject()
        {
            if (!Expect('{'))
            {
                return false;
            }

            SkipWhitespace();

            if (Consume('}'))
            {
                return true;
            }

            while (true)
            {
                std::string ignoredKey;

                if (
                    !ParseString(ignoredKey) ||
                    !Expect(':') ||
                    !SkipValue()
                )
                {
                    return false;
                }

                SkipWhitespace();

                if (Consume('}'))
                {
                    return true;
                }

                if (!Expect(','))
                {
                    return false;
                }
            }
        }

        bool SkipArray()
        {
            if (!Expect('['))
            {
                return false;
            }

            SkipWhitespace();

            if (Consume(']'))
            {
                return true;
            }

            while (true)
            {
                if (!SkipValue())
                {
                    return false;
                }

                SkipWhitespace();

                if (Consume(']'))
                {
                    return true;
                }

                if (!Expect(','))
                {
                    return false;
                }
            }
        }

        bool SkipLiteral(std::string_view literal)
        {
            if (
                source_.substr(position_, literal.size()) != literal
            )
            {
                return Fail("An invalid JSON literal was found");
            }

            position_ += literal.size();
            return true;
        }

        bool SkipNumber()
        {
            const std::size_t start = position_;

            if (
                position_ < source_.size() &&
                source_[position_] == '-'
            )
            {
                ++position_;
            }

            if (position_ >= source_.size())
            {
                return Fail("A JSON number is incomplete");
            }

            if (source_[position_] == '0')
            {
                ++position_;
            }
            else
            {
                if (
                    source_[position_] < '1' ||
                    source_[position_] > '9'
                )
                {
                    return Fail("An invalid JSON value was found");
                }

                while (
                    position_ < source_.size() &&
                    source_[position_] >= '0' &&
                    source_[position_] <= '9'
                )
                {
                    ++position_;
                }
            }

            if (
                position_ < source_.size() &&
                source_[position_] == '.'
            )
            {
                ++position_;

                if (
                    position_ >= source_.size() ||
                    source_[position_] < '0' ||
                    source_[position_] > '9'
                )
                {
                    return Fail("A JSON fraction is invalid");
                }

                while (
                    position_ < source_.size() &&
                    source_[position_] >= '0' &&
                    source_[position_] <= '9'
                )
                {
                    ++position_;
                }
            }

            if (
                position_ < source_.size() &&
                (
                    source_[position_] == 'e' ||
                    source_[position_] == 'E'
                )
            )
            {
                ++position_;

                if (
                    position_ < source_.size() &&
                    (
                        source_[position_] == '+' ||
                        source_[position_] == '-'
                    )
                )
                {
                    ++position_;
                }

                if (
                    position_ >= source_.size() ||
                    source_[position_] < '0' ||
                    source_[position_] > '9'
                )
                {
                    return Fail("A JSON exponent is invalid");
                }

                while (
                    position_ < source_.size() &&
                    source_[position_] >= '0' &&
                    source_[position_] <= '9'
                )
                {
                    ++position_;
                }
            }

            if (position_ == start)
            {
                return Fail("An invalid JSON number was found");
            }

            return true;
        }

        bool Fail(const std::string& message)
        {
            if (error_.empty())
            {
                error_ =
                    message +
                    " at byte " +
                    std::to_string(position_);
            }

            return false;
        }

        std::string_view source_;
        std::size_t position_ = 0;
        std::string error_;
    };

    bool ParseServerAddress(
        ServerEntry& server,
        std::string& error)
    {
        const std::size_t separator = server.address.rfind(':');

        if (
            separator == std::string::npos ||
            separator == 0 ||
            separator + 1 >= server.address.size()
        )
        {
            error =
                "Server " +
                server.name +
                " has an invalid address: " +
                server.address;

            return false;
        }

        server.ip = server.address.substr(0, separator);
        const std::string portText =
            server.address.substr(separator + 1);

        unsigned int parsedPort = 0;
        const auto result = std::from_chars(
            portText.data(),
            portText.data() + portText.size(),
            parsedPort
        );

        if (
            result.ec != std::errc{} ||
            result.ptr != portText.data() + portText.size() ||
            parsedPort == 0 ||
            parsedPort > 65535
        )
        {
            error =
                "Server " +
                server.name +
                " has an invalid port: " +
                server.address;

            return false;
        }

        IN_ADDR ipv4Address{};

        if (
            InetPtonA(
                AF_INET,
                server.ip.c_str(),
                &ipv4Address
            ) != 1
        )
        {
            error =
                "Server " +
                server.name +
                " has an invalid IPv4 address: " +
                server.ip;

            return false;
        }

        server.port = static_cast<std::uint16_t>(parsedPort);
        return true;
    }

    bool ReadFile(
        const std::filesystem::path& path,
        std::string& content,
        std::string& error)
    {
        std::ifstream stream(path, std::ios::binary);

        if (!stream)
        {
            error =
                "Unable to open " +
                path.string();

            return false;
        }

        content.assign(
            std::istreambuf_iterator<char>(stream),
            std::istreambuf_iterator<char>()
        );

        if (
            content.size() >= 3 &&
            static_cast<unsigned char>(content[0]) == 0xEF &&
            static_cast<unsigned char>(content[1]) == 0xBB &&
            static_cast<unsigned char>(content[2]) == 0xBF
        )
        {
            content.erase(0, 3);
        }

        if (content.empty())
        {
            error = "Servers.json is empty";
            return false;
        }

        return true;
    }

    bool ReadEmbeddedResource(
        int resourceId,
        const void*& data,
        DWORD& size)
    {
        data = nullptr;
        size = 0;

        const HMODULE module = GetModuleHandleW(nullptr);

        if (!module)
        {
            return false;
        }

        const HRSRC resourceInfo = FindResourceW(
            module,
            MAKEINTRESOURCEW(resourceId),
            RT_RCDATA
        );

        if (!resourceInfo)
        {
            return false;
        }

        const HGLOBAL resource = LoadResource(
            module,
            resourceInfo
        );

        if (!resource)
        {
            return false;
        }

        size = SizeofResource(module, resourceInfo);
        data = LockResource(resource);

        return data != nullptr && size != 0;
    }

    bool ReadEmbeddedTextResource(
        int resourceId,
        std::string& content,
        std::string& error)
    {
        const void* data = nullptr;
        DWORD size = 0;

        if (!ReadEmbeddedResource(resourceId, data, size))
        {
            error =
                "The embedded Servers.json resource could not "
                "be loaded.";

            return false;
        }

        content.assign(
            static_cast<const char*>(data),
            static_cast<std::size_t>(size)
        );

        if (
            content.size() >= 3 &&
            static_cast<unsigned char>(content[0]) == 0xEF &&
            static_cast<unsigned char>(content[1]) == 0xBB &&
            static_cast<unsigned char>(content[2]) == 0xBF
        )
        {
            content.erase(0, 3);
        }

        if (content.empty())
        {
            error = "The embedded Servers.json is empty.";
            return false;
        }

        return true;
    }

    std::filesystem::path FindServersJson()
    {
        constexpr DWORD maximumPathLength = 32768;
        std::vector<wchar_t> executablePath(
            maximumPathLength,
            L'\0'
        );

        const DWORD executableLength = GetModuleFileNameW(
            nullptr,
            executablePath.data(),
            maximumPathLength
        );

        if (
            executableLength == 0 ||
            executableLength >= maximumPathLength
        )
        {
            return {};
        }

        const std::filesystem::path candidate =
            std::filesystem::path(
                executablePath.data()
            ).parent_path() / L"Servers.json";

        std::error_code fileError;

        if (
            std::filesystem::is_regular_file(
                candidate,
                fileError
            ) &&
            !fileError
        )
        {
            return candidate;
        }

        return {};
    }

    std::filesystem::path GetExecutableDirectory()
    {
        constexpr DWORD maximumPathLength = 32768;
        std::vector<wchar_t> executablePath(
            maximumPathLength,
            L'\0'
        );

        const DWORD executableLength = GetModuleFileNameW(
            nullptr,
            executablePath.data(),
            maximumPathLength
        );

        if (
            executableLength == 0 ||
            executableLength >= maximumPathLength
        )
        {
            return {};
        }

        return std::filesystem::path(
            executablePath.data()
        ).parent_path();
    }

    HICON LoadExternalApplicationIcon(
        int width,
        int height)
    {
        const std::filesystem::path directory =
            GetExecutableDirectory();

        if (directory.empty())
        {
            return nullptr;
        }

        const std::filesystem::path iconPath =
            directory / L"app.ico";

        return reinterpret_cast<HICON>(
            LoadImageW(
                nullptr,
                iconPath.c_str(),
                IMAGE_ICON,
                width,
                height,
                LR_LOADFROMFILE |
                LR_DEFAULTCOLOR
            )
        );
    }

    HICON LoadEmbeddedApplicationIcon(
        HINSTANCE instance,
        int width,
        int height)
    {
        return reinterpret_cast<HICON>(
            LoadImageW(
                instance,
                MAKEINTRESOURCEW(IDI_APP_ICON),
                IMAGE_ICON,
                width,
                height,
                LR_SHARED |
                LR_DEFAULTCOLOR
            )
        );
    }

    void UnloadExternalApplicationIcons()
    {
        if (g_largeExternalIcon)
        {
            DestroyIcon(g_largeExternalIcon);
            g_largeExternalIcon = nullptr;
        }

        if (g_smallExternalIcon)
        {
            DestroyIcon(g_smallExternalIcon);
            g_smallExternalIcon = nullptr;
        }
    }

    bool LoadEmbeddedFontResource(int resourceId)
    {
        const void* data = nullptr;
        DWORD size = 0;

        if (!ReadEmbeddedResource(resourceId, data, size))
        {
            return false;
        }

        DWORD fontCount = 0;
        const HANDLE fontHandle = AddFontMemResourceEx(
            const_cast<void*>(data),
            size,
            nullptr,
            &fontCount
        );

        if (!fontHandle)
        {
            return false;
        }

        if (fontCount == 0)
        {
            RemoveFontMemResourceEx(fontHandle);
            return false;
        }

        g_loadedMemoryFonts.push_back(fontHandle);
        return true;
    }

    void LoadOrbitronFonts()
    {
        g_loadedFontFiles.clear();
        g_loadedMemoryFonts.clear();
        g_orbitronLoaded = false;

        const bool regularFontLoaded =
            LoadEmbeddedFontResource(
                IDR_ORBITRON_REGULAR
            );

        const bool semiboldFontLoaded =
            LoadEmbeddedFontResource(
                IDR_ORBITRON_SEMIBOLD
            );

        if (regularFontLoaded && semiboldFontLoaded)
        {
            g_orbitronLoaded = true;
            return;
        }

        std::vector<std::filesystem::path>
            searchDirectories;

        const std::filesystem::path executableDirectory =
            GetExecutableDirectory();

        if (!executableDirectory.empty())
        {
            searchDirectories.push_back(
                executableDirectory / L"fonts"
            );

            searchDirectories.push_back(
                executableDirectory
            );
        }

        std::error_code currentPathError;
        const std::filesystem::path currentDirectory =
            std::filesystem::current_path(
                currentPathError
            );

        if (!currentPathError)
        {
            searchDirectories.push_back(
                currentDirectory / L"fonts"
            );
        }

        const std::vector<std::filesystem::path>
            fontNames{
                L"Orbitron-Regular.ttf",
                L"Orbitron-SemiBold.ttf"
            };

        std::set<std::filesystem::path> checkedFiles;

        for (const auto& directory : searchDirectories)
        {
            for (const auto& fontName : fontNames)
            {
                const std::filesystem::path fontPath =
                    directory / fontName;

                if (!checkedFiles.insert(fontPath).second)
                {
                    continue;
                }

                std::error_code fileError;

                if (
                    !std::filesystem::is_regular_file(
                        fontPath,
                        fileError
                    ) ||
                    fileError
                )
                {
                    continue;
                }

                if (
                    AddFontResourceExW(
                        fontPath.c_str(),
                        FR_PRIVATE,
                        nullptr
                    ) > 0
                )
                {
                    g_loadedFontFiles.push_back(
                        fontPath
                    );
                }
            }
        }

        g_orbitronLoaded =
            !g_loadedMemoryFonts.empty() ||
            !g_loadedFontFiles.empty();
    }

    void UnloadOrbitronFonts()
    {
        for (
            auto iterator = g_loadedFontFiles.rbegin();
            iterator != g_loadedFontFiles.rend();
            ++iterator
        )
        {
            RemoveFontResourceExW(
                iterator->c_str(),
                FR_PRIVATE,
                nullptr
            );
        }

        g_loadedFontFiles.clear();

        for (
            auto iterator = g_loadedMemoryFonts.rbegin();
            iterator != g_loadedMemoryFonts.rend();
            ++iterator
        )
        {
            RemoveFontMemResourceEx(*iterator);
        }

        g_loadedMemoryFonts.clear();
        g_orbitronLoaded = false;
    }

    bool LoadServers(
        std::vector<ServerPool>& pools,
        std::filesystem::path& loadedPath,
        std::string& error)
    {
        loadedPath = FindServersJson();
        std::string content;

        if (!loadedPath.empty())
        {
            if (!ReadFile(loadedPath, content, error))
            {
                return false;
            }
        }
        else if (
            !ReadEmbeddedTextResource(
                IDR_SERVERS_JSON,
                content,
                error
            )
        )
        {
            return false;
        }

        ServersJsonParser parser(content);

        if (!parser.Parse(pools))
        {
            error =
                "Servers.json is invalid: " +
                parser.Error();

            return false;
        }

        std::size_t serverCount = 0;

        for (auto& pool : pools)
        {
            for (auto& server : pool.servers)
            {
                if (!ParseServerAddress(server, error))
                {
                    return false;
                }

                ++serverCount;
            }
        }

        if (serverCount == 0)
        {
            error = "Servers.json does not contain any servers";
            return false;
        }

        return true;
    }

    bool IsRunningAsAdministrator()
    {
        SID_IDENTIFIER_AUTHORITY authority =
            SECURITY_NT_AUTHORITY;

        PSID administratorsGroup = nullptr;

        if (
            !AllocateAndInitializeSid(
                &authority,
                2,
                SECURITY_BUILTIN_DOMAIN_RID,
                DOMAIN_ALIAS_RID_ADMINS,
                0,
                0,
                0,
                0,
                0,
                0,
                &administratorsGroup
            )
        )
        {
            return false;
        }

        BOOL isAdministrator = FALSE;

        const BOOL checkResult = CheckTokenMembership(
            nullptr,
            administratorsGroup,
            &isAdministrator
        );

        FreeSid(administratorsGroup);

        return
            checkResult != FALSE &&
            isAdministrator != FALSE;
    }

    bool RelaunchAsAdministrator()
    {
        constexpr DWORD maximumPathLength = 32768;
        std::vector<wchar_t> executablePath(
            maximumPathLength,
            L'\0'
        );

        const DWORD executableLength = GetModuleFileNameW(
            nullptr,
            executablePath.data(),
            maximumPathLength
        );

        if (
            executableLength == 0 ||
            executableLength >= maximumPathLength
        )
        {
            return false;
        }

        SHELLEXECUTEINFOW executeInfo{};
        executeInfo.cbSize = sizeof(executeInfo);
        executeInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        executeInfo.hwnd = nullptr;
        executeInfo.lpVerb = L"runas";
        executeInfo.lpFile = executablePath.data();
        executeInfo.nShow = SW_SHOWNORMAL;

        if (!ShellExecuteExW(&executeInfo))
        {
            return false;
        }

        if (executeInfo.hProcess)
        {
            CloseHandle(executeInfo.hProcess);
        }

        return true;
    }

    class ScopedBstr
    {
    public:
        explicit ScopedBstr(std::wstring_view text)
            : value_(
                SysAllocStringLen(
                    text.data(),
                    static_cast<UINT>(text.size())
                )
            )
        {
        }

        ~ScopedBstr()
        {
            SysFreeString(value_);
        }

        ScopedBstr(const ScopedBstr&) = delete;
        ScopedBstr& operator=(const ScopedBstr&) = delete;

        BSTR Get() const
        {
            return value_;
        }

        bool IsValid() const
        {
            return value_ != nullptr;
        }

    private:
        BSTR value_ = nullptr;
    };

    HRESULT GetFirewallRules(INetFwRules** rules)
    {
        if (!rules)
        {
            return E_POINTER;
        }

        *rules = nullptr;

        INetFwPolicy2* policy = nullptr;

        HRESULT result = CoCreateInstance(
            __uuidof(NetFwPolicy2),
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&policy)
        );

        if (FAILED(result))
        {
            return result;
        }

        result = policy->get_Rules(rules);
        policy->Release();
        return result;
    }

    HRESULT EnsureServiceRunning(
        const wchar_t* serviceName)
    {
        if (!serviceName || *serviceName == L'\0')
        {
            return E_INVALIDARG;
        }

        SC_HANDLE serviceManager = OpenSCManagerW(
            nullptr,
            nullptr,
            SC_MANAGER_CONNECT
        );

        if (!serviceManager)
        {
            return HRESULT_FROM_WIN32(
                GetLastError()
            );
        }

        SC_HANDLE service = OpenServiceW(
            serviceManager,
            serviceName,
            SERVICE_QUERY_STATUS |
            SERVICE_START
        );

        if (!service)
        {
            const HRESULT result =
                HRESULT_FROM_WIN32(GetLastError());
            CloseServiceHandle(serviceManager);
            return result;
        }

        SERVICE_STATUS_PROCESS status{};
        DWORD bytesNeeded = 0;

        if (!QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE*>(&status),
                sizeof(status),
                &bytesNeeded))
        {
            const HRESULT result =
                HRESULT_FROM_WIN32(GetLastError());
            CloseServiceHandle(service);
            CloseServiceHandle(serviceManager);
            return result;
        }

        HRESULT result = S_OK;

        if (status.dwCurrentState != SERVICE_RUNNING)
        {
            if (!StartServiceW(service, 0, nullptr))
            {
                DWORD error = GetLastError();

                if (error == ERROR_SERVICE_DISABLED)
                {
                    SC_HANDLE configurableService =
                        OpenServiceW(
                            serviceManager,
                            serviceName,
                            SERVICE_CHANGE_CONFIG
                        );

                    if (!configurableService)
                    {
                        error = GetLastError();
                    }
                    else
                    {
                        if (!ChangeServiceConfigW(
                                configurableService,
                                SERVICE_NO_CHANGE,
                                SERVICE_AUTO_START,
                                SERVICE_NO_CHANGE,
                                nullptr,
                                nullptr,
                                nullptr,
                                nullptr,
                                nullptr,
                                nullptr,
                                nullptr))
                        {
                            error = GetLastError();
                        }
                        else if (
                            !StartServiceW(
                                service,
                                0,
                                nullptr
                            )
                        )
                        {
                            error = GetLastError();
                        }
                        else
                        {
                            error = ERROR_SUCCESS;
                        }

                        CloseServiceHandle(
                            configurableService
                        );
                    }
                }

                if (
                    error != ERROR_SUCCESS &&
                    error != ERROR_SERVICE_ALREADY_RUNNING
                )
                {
                    result =
                        HRESULT_FROM_WIN32(error);
                }
            }

            const ULONGLONG deadline =
                GetTickCount64() + 10000;

            while (
                SUCCEEDED(result) &&
                GetTickCount64() < deadline
            )
            {
                if (!QueryServiceStatusEx(
                        service,
                        SC_STATUS_PROCESS_INFO,
                        reinterpret_cast<BYTE*>(&status),
                        sizeof(status),
                        &bytesNeeded))
                {
                    result = HRESULT_FROM_WIN32(
                        GetLastError()
                    );
                    break;
                }

                if (
                    status.dwCurrentState ==
                    SERVICE_RUNNING
                )
                {
                    break;
                }

                if (
                    status.dwCurrentState ==
                    SERVICE_STOPPED
                )
                {
                    result = HRESULT_FROM_WIN32(
                        status.dwWin32ExitCode !=
                            ERROR_SUCCESS
                        ? status.dwWin32ExitCode
                        : ERROR_SERVICE_NOT_ACTIVE
                    );
                    break;
                }

                Sleep(100);
            }

            if (
                SUCCEEDED(result) &&
                status.dwCurrentState != SERVICE_RUNNING
            )
            {
                result = HRESULT_FROM_WIN32(
                    ERROR_SERVICE_REQUEST_TIMEOUT
                );
            }
        }

        CloseServiceHandle(service);
        CloseServiceHandle(serviceManager);
        return result;
    }

    HRESULT EnsureWindowsFirewallServicesRunning()
    {
        HRESULT result =
            EnsureServiceRunning(L"BFE");

        if (FAILED(result))
        {
            return result;
        }

        return EnsureServiceRunning(L"MpsSvc");
    }

    HRESULT EnsureCurrentFirewallProfilesEnabled()
    {
        HRESULT result =
            EnsureWindowsFirewallServicesRunning();

        if (FAILED(result))
        {
            return result;
        }

        INetFwPolicy2* policy = nullptr;

        result = CoCreateInstance(
            __uuidof(NetFwPolicy2),
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&policy)
        );

        if (FAILED(result))
        {
            return result;
        }

        long currentProfiles = 0;
        result = policy->get_CurrentProfileTypes(
            &currentProfiles
        );

        constexpr NET_FW_PROFILE_TYPE2 profiles[] =
        {
            NET_FW_PROFILE2_DOMAIN,
            NET_FW_PROFILE2_PRIVATE,
            NET_FW_PROFILE2_PUBLIC
        };

        for (
            const NET_FW_PROFILE_TYPE2 profile : profiles
        )
        {
            if (
                FAILED(result) ||
                (currentProfiles & profile) == 0
            )
            {
                continue;
            }

            VARIANT_BOOL enabled = VARIANT_FALSE;
            result = policy->get_FirewallEnabled(
                profile,
                &enabled
            );

            if (SUCCEEDED(result) &&
                enabled != VARIANT_TRUE)
            {
                result = policy->put_FirewallEnabled(
                    profile,
                    VARIANT_TRUE
                );

                if (SUCCEEDED(result))
                {
                    enabled = VARIANT_FALSE;
                    result = policy->get_FirewallEnabled(
                        profile,
                        &enabled
                    );
                }

                if (SUCCEEDED(result) &&
                    enabled != VARIANT_TRUE)
                {
                    result = E_ACCESSDENIED;
                }
            }
        }

        policy->Release();
        return result;
    }

    HRESULT RemoveRuleIfPresent(
        INetFwRules* rules,
        std::wstring_view ruleName)
    {
        if (!rules)
        {
            return E_POINTER;
        }

        ScopedBstr name(ruleName);

        if (!name.IsValid())
        {
            return E_OUTOFMEMORY;
        }

        INetFwRule* existingRule = nullptr;
        const HRESULT itemResult = rules->Item(
            name.Get(),
            &existingRule
        );

        if (SUCCEEDED(itemResult))
        {
            existingRule->Release();
            return rules->Remove(name.Get());
        }

        if (
            itemResult == HRESULT_FROM_WIN32(
                ERROR_FILE_NOT_FOUND
            ) ||
            itemResult == HRESULT_FROM_WIN32(
                ERROR_NOT_FOUND
            )
        )
        {
            return S_OK;
        }

        return itemResult;
    }

    HRESULT RemoveFirewallRules(INetFwRules* rules)
    {
        HRESULT result = RemoveRuleIfPresent(
            rules,
            ALL_OUTBOUND_RULE_NAME
        );

        if (FAILED(result))
        {
            return result;
        }

        result = RemoveRuleIfPresent(
            rules,
            ALL_INBOUND_RULE_NAME
        );

        if (FAILED(result))
        {
            return result;
        }

        result = RemoveRuleIfPresent(
            rules,
            LEGACY_UDP_RULE_NAME
        );

        if (FAILED(result))
        {
            return result;
        }

        result = RemoveRuleIfPresent(
            rules,
            LEGACY_TCP_RULE_NAME
        );

        if (FAILED(result))
        {
            return result;
        }

        result = RemoveRuleIfPresent(
            rules,
            LEGACY_UDP_INBOUND_RULE_NAME
        );

        if (FAILED(result))
        {
            return result;
        }

        return RemoveRuleIfPresent(
            rules,
            LEGACY_TCP_INBOUND_RULE_NAME
        );
    }

    HRESULT RemoveFirewallRules()
    {
        INetFwRules* rules = nullptr;
        HRESULT result = GetFirewallRules(&rules);

        if (FAILED(result))
        {
            return result;
        }

        result = RemoveFirewallRules(rules);
        rules->Release();
        return result;
    }

    HRESULT AddFirewallRule(
        INetFwRules* rules,
        std::wstring_view ruleName,
        long protocol,
        NET_FW_RULE_DIRECTION direction,
        std::wstring_view remoteAddresses)
    {
        if (!rules)
        {
            return E_POINTER;
        }

        const auto setStage =
            [ruleName](std::wstring_view property)
        {
            g_firewallOperationStage =
                std::wstring(ruleName) +
                L": " +
                std::wstring(property);
        };

        setStage(L"creating rule object");

        INetFwRule* rule = nullptr;

        HRESULT result = CoCreateInstance(
            __uuidof(NetFwRule),
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&rule)
        );

        if (FAILED(result))
        {
            return result;
        }

        ScopedBstr name(ruleName);
        ScopedBstr description(
            L"Blocks all IP traffic to or from selected "
            L"STALZONE server addresses system-wide."
        );
        ScopedBstr grouping(FIREWALL_GROUP_NAME);
        ScopedBstr addresses(remoteAddresses);
        ScopedBstr localAddresses(L"*");
        ScopedBstr interfaceTypes(L"All");

        if (
            !name.IsValid() ||
            !description.IsValid() ||
            !grouping.IsValid() ||
            !addresses.IsValid() ||
            !localAddresses.IsValid() ||
            !interfaceTypes.IsValid()
        )
        {
            rule->Release();
            return E_OUTOFMEMORY;
        }

        setStage(L"setting name");
        result = rule->put_Name(name.Get());

        if (SUCCEEDED(result))
        {
            setStage(L"setting description");
            result = rule->put_Description(
                description.Get()
            );
        }

        if (SUCCEEDED(result))
        {
            setStage(L"setting protocol");
            result = rule->put_Protocol(protocol);
        }

        if (SUCCEEDED(result))
        {
            setStage(L"setting remote addresses");
            result = rule->put_RemoteAddresses(
                addresses.Get()
            );
        }

        if (SUCCEEDED(result))
        {
            setStage(L"setting local addresses");
            result = rule->put_LocalAddresses(
                localAddresses.Get()
            );
        }

        if (SUCCEEDED(result))
        {
            setStage(L"setting direction");
            result = rule->put_Direction(
                direction
            );
        }

        if (SUCCEEDED(result))
        {
            setStage(L"setting block action");
            result = rule->put_Action(
                NET_FW_ACTION_BLOCK
            );
        }

        if (SUCCEEDED(result))
        {
            setStage(L"setting firewall profiles");
            result = rule->put_Profiles(
                NET_FW_PROFILE2_ALL
            );
        }

        if (SUCCEEDED(result))
        {
            setStage(L"setting interface types");
            result = rule->put_InterfaceTypes(
                interfaceTypes.Get()
            );
        }

        if (SUCCEEDED(result))
        {
            setStage(L"disabling edge traversal");
            result = rule->put_EdgeTraversal(
                VARIANT_FALSE
            );
        }

        if (SUCCEEDED(result))
        {
            setStage(L"enabling rule");
            result = rule->put_Enabled(
                VARIANT_TRUE
            );
        }

        if (SUCCEEDED(result))
        {
            setStage(L"setting rule group");
            result = rule->put_Grouping(
                grouping.Get()
            );
        }

        if (SUCCEEDED(result))
        {
            setStage(L"adding rule to Windows Firewall");
            result = rules->Add(rule);
        }

        rule->Release();
        return result;
    }

    std::wstring JoinRemoteAddresses(
        const std::vector<std::string>& addresses)
    {
        std::wstring result;

        for (std::size_t index = 0;
             index < addresses.size();
             ++index)
        {
            if (index != 0)
            {
                result.push_back(L',');
            }

            result += Utf8ToWide(addresses[index]);
        }

        return result;
    }

    HRESULT VerifyFirewallRule(
        INetFwRules* rules,
        std::wstring_view ruleName,
        NET_FW_RULE_DIRECTION expectedDirection,
        const std::vector<std::string>& expectedAddresses)
    {
        if (!rules)
        {
            return E_POINTER;
        }

        const auto setVerificationStage =
            [ruleName](std::wstring_view detail)
        {
            g_firewallOperationStage =
                std::wstring(L"Verifying ") +
                std::wstring(ruleName) +
                L": " +
                std::wstring(detail);
        };

        setVerificationStage(L"opening rule");

        ScopedBstr name(ruleName);

        if (!name.IsValid())
        {
            return E_OUTOFMEMORY;
        }

        INetFwRule* rule = nullptr;
        HRESULT result = rules->Item(
            name.Get(),
            &rule
        );

        if (FAILED(result))
        {
            return result;
        }

        long protocol = 0;
        NET_FW_RULE_DIRECTION direction =
            NET_FW_RULE_DIR_MAX;
        NET_FW_ACTION action =
            NET_FW_ACTION_MAX;
        VARIANT_BOOL enabled = VARIANT_FALSE;
        long profiles = 0;
        BSTR rawAddresses = nullptr;

        result = rule->get_Protocol(&protocol);

        if (SUCCEEDED(result))
        {
            result = rule->get_Direction(&direction);
        }

        if (SUCCEEDED(result))
        {
            result = rule->get_Action(&action);
        }

        if (SUCCEEDED(result))
        {
            result = rule->get_Enabled(&enabled);
        }

        if (SUCCEEDED(result))
        {
            result = rule->get_Profiles(&profiles);
        }

        if (SUCCEEDED(result))
        {
            result = rule->get_RemoteAddresses(
                &rawAddresses
            );
        }

        rule->Release();

        if (FAILED(result))
        {
            setVerificationStage(
                L"reading rule properties"
            );

            if (rawAddresses)
            {
                SysFreeString(rawAddresses);
            }

            return result;
        }

        constexpr long requiredProfiles =
            NET_FW_PROFILE2_DOMAIN |
            NET_FW_PROFILE2_PRIVATE |
            NET_FW_PROFILE2_PUBLIC;

        const auto invalidProperty =
            [&rawAddresses, &setVerificationStage](
                std::wstring_view detail)
        {
            setVerificationStage(detail);

            if (rawAddresses)
            {
                SysFreeString(rawAddresses);
                rawAddresses = nullptr;
            }

            return HRESULT_FROM_WIN32(
                ERROR_INVALID_DATA
            );
        };

        if (protocol != NET_FW_IP_PROTOCOL_ANY)
        {
            return invalidProperty(
                L"unexpected protocol"
            );
        }

        if (direction != expectedDirection)
        {
            return invalidProperty(
                L"unexpected direction"
            );
        }

        if (action != NET_FW_ACTION_BLOCK)
        {
            return invalidProperty(
                L"unexpected action"
            );
        }

        if (enabled != VARIANT_TRUE)
        {
            return invalidProperty(
                L"rule is disabled"
            );
        }

        if (
            (profiles & requiredProfiles) !=
            requiredProfiles
        )
        {
            return invalidProperty(
                L"incomplete profile mask"
            );
        }

        if (!rawAddresses)
        {
            return invalidProperty(
                L"remote address list is empty"
            );
        }

        std::unordered_set<std::string> actualAddresses;
        std::wstring values(
            rawAddresses,
            SysStringLen(rawAddresses)
        );
        SysFreeString(rawAddresses);

        std::size_t start = 0;

        while (start <= values.size())
        {
            const std::size_t separator =
                values.find(L',', start);

            const std::size_t length =
                separator == std::wstring::npos
                ? values.size() - start
                : separator - start;

            std::wstring value =
                values.substr(start, length);

            value.erase(
                std::remove_if(
                    value.begin(),
                    value.end(),
                    [](wchar_t character)
                    {
                        return iswspace(character);
                    }
                ),
                value.end()
            );

            if (!value.empty())
            {
                std::string normalized =
                    WideToUtf8(value);

                constexpr std::string_view suffixes[] =
                {
                    "/32",
                    "/255.255.255.255"
                };

                for (const std::string_view suffix :
                     suffixes)
                {
                    if (normalized.ends_with(suffix))
                    {
                        normalized.resize(
                            normalized.size() -
                            suffix.size()
                        );
                        break;
                    }
                }

                actualAddresses.insert(
                    std::move(normalized)
                );
            }

            if (separator == std::wstring::npos)
            {
                break;
            }

            start = separator + 1;
        }

        for (const std::string& address :
             expectedAddresses)
        {
            if (!actualAddresses.contains(address))
            {
                setVerificationStage(
                    L"missing remote IP " +
                    Utf8ToWide(address)
                );

                return HRESULT_FROM_WIN32(
                    ERROR_INVALID_DATA
                );
            }
        }

        return S_OK;
    }

    HRESULT ApplyFirewallRules(
        const std::vector<std::string>& addresses)
    {
        if (addresses.empty())
        {
            return E_INVALIDARG;
        }

        g_firewallOperationStage =
            L"Checking firewall services and profiles";

        HRESULT result =
            EnsureCurrentFirewallProfilesEnabled();

        if (FAILED(result))
        {
            return result;
        }

        INetFwRules* rules = nullptr;
        g_firewallOperationStage =
            L"Opening Windows Firewall policy";
        result = GetFirewallRules(&rules);

        if (FAILED(result))
        {
            return result;
        }

        g_firewallOperationStage =
            L"Removing previous program rules";
        result = RemoveFirewallRules(rules);

        if (SUCCEEDED(result))
        {
            const std::wstring remoteAddresses =
                JoinRemoteAddresses(addresses);

            result = AddFirewallRule(
                rules,
                ALL_OUTBOUND_RULE_NAME,
                NET_FW_IP_PROTOCOL_ANY,
                NET_FW_RULE_DIR_OUT,
                remoteAddresses
            );

            if (SUCCEEDED(result))
            {
                result = AddFirewallRule(
                    rules,
                    ALL_INBOUND_RULE_NAME,
                    NET_FW_IP_PROTOCOL_ANY,
                    NET_FW_RULE_DIR_IN,
                    remoteAddresses
                );
            }

            if (SUCCEEDED(result))
            {
                g_firewallOperationStage =
                    L"Verifying outbound all-protocol rule";
                result = VerifyFirewallRule(
                    rules,
                    ALL_OUTBOUND_RULE_NAME,
                    NET_FW_RULE_DIR_OUT,
                    addresses
                );
            }

            if (SUCCEEDED(result))
            {
                g_firewallOperationStage =
                    L"Verifying inbound all-protocol rule";
                result = VerifyFirewallRule(
                    rules,
                    ALL_INBOUND_RULE_NAME,
                    NET_FW_RULE_DIR_IN,
                    addresses
                );
            }
        }

        if (FAILED(result))
        {
            RemoveFirewallRules(rules);
        }

        rules->Release();

        if (SUCCEEDED(result))
        {
            g_firewallOperationStage.clear();
        }

        return result;
    }

    std::size_t TerminateTcpConnections(
        const std::vector<std::string>& addresses)
    {
        std::unordered_set<ULONG> remoteAddresses;

        for (const auto& addressText : addresses)
        {
            IN_ADDR address{};

            if (
                InetPtonA(
                    AF_INET,
                    addressText.c_str(),
                    &address
                ) == 1
            )
            {
                remoteAddresses.insert(
                    address.S_un.S_addr
                );
            }
        }

        if (remoteAddresses.empty())
        {
            return 0;
        }

        DWORD bufferSize = 0;
        DWORD tableResult = GetTcpTable(
            nullptr,
            &bufferSize,
            FALSE
        );

        if (
            tableResult != ERROR_INSUFFICIENT_BUFFER ||
            bufferSize == 0
        )
        {
            return 0;
        }

        std::vector<DWORD> buffer(
            (
                static_cast<std::size_t>(bufferSize) +
                sizeof(DWORD) - 1
            ) / sizeof(DWORD)
        );

        auto* table = reinterpret_cast<PMIB_TCPTABLE>(
            buffer.data()
        );

        tableResult = GetTcpTable(
            table,
            &bufferSize,
            FALSE
        );

        if (tableResult != NO_ERROR)
        {
            return 0;
        }

        std::size_t terminatedCount = 0;

        for (
            DWORD index = 0;
            index < table->dwNumEntries;
            ++index
        )
        {
            MIB_TCPROW row = table->table[index];

            if (
                !remoteAddresses.contains(
                    row.dwRemoteAddr
                ) ||
                row.dwState == MIB_TCP_STATE_LISTEN
            )
            {
                continue;
            }

            row.dwState = MIB_TCP_STATE_DELETE_TCB;

            if (SetTcpEntry(&row) == NO_ERROR)
            {
                ++terminatedCount;
            }
        }

        return terminatedCount;
    }

    std::wstring Trim(std::wstring value)
    {
        const auto isNotWhitespace = [](wchar_t character)
        {
            return !iswspace(character);
        };

        value.erase(
            value.begin(),
            std::find_if(
                value.begin(),
                value.end(),
                isNotWhitespace
            )
        );

        value.erase(
            std::find_if(
                value.rbegin(),
                value.rend(),
                isNotWhitespace
            ).base(),
            value.end()
        );

        return value;
    }

    void AddAddressesFromRule(
        INetFwRules* rules,
        std::wstring_view ruleName,
        NET_FW_RULE_DIRECTION expectedDirection,
        std::unordered_set<std::string>& addresses,
        bool& ruleExists)
    {
        ScopedBstr name(ruleName);

        if (!name.IsValid())
        {
            return;
        }

        INetFwRule* rule = nullptr;

        if (
            FAILED(
                rules->Item(
                    name.Get(),
                    &rule
                )
            )
        )
        {
            return;
        }

        long protocol = 0;
        NET_FW_RULE_DIRECTION direction =
            NET_FW_RULE_DIR_MAX;
        NET_FW_ACTION action =
            NET_FW_ACTION_MAX;
        VARIANT_BOOL enabled = VARIANT_FALSE;
        long profiles = 0;

        HRESULT propertyResult =
            rule->get_Protocol(&protocol);

        if (SUCCEEDED(propertyResult))
        {
            propertyResult =
                rule->get_Direction(&direction);
        }

        if (SUCCEEDED(propertyResult))
        {
            propertyResult =
                rule->get_Action(&action);
        }

        if (SUCCEEDED(propertyResult))
        {
            propertyResult =
                rule->get_Enabled(&enabled);
        }

        if (SUCCEEDED(propertyResult))
        {
            propertyResult =
                rule->get_Profiles(&profiles);
        }

        constexpr long requiredProfiles =
            NET_FW_PROFILE2_DOMAIN |
            NET_FW_PROFILE2_PRIVATE |
            NET_FW_PROFILE2_PUBLIC;

        if (
            FAILED(propertyResult) ||
            protocol != NET_FW_IP_PROTOCOL_ANY ||
            direction != expectedDirection ||
            action != NET_FW_ACTION_BLOCK ||
            enabled != VARIANT_TRUE ||
            (profiles & requiredProfiles) !=
                requiredProfiles
        )
        {
            rule->Release();
            return;
        }

        ruleExists = true;
        BSTR rawAddresses = nullptr;

        if (
            SUCCEEDED(
                rule->get_RemoteAddresses(
                    &rawAddresses
                )
            ) &&
            rawAddresses
        )
        {
            std::wstring values(
                rawAddresses,
                SysStringLen(rawAddresses)
            );

            std::size_t start = 0;

            while (start <= values.size())
            {
                const std::size_t separator =
                    values.find(L',', start);

                const std::size_t length =
                    separator == std::wstring::npos
                    ? values.size() - start
                    : separator - start;

                const std::wstring value = Trim(
                    values.substr(start, length)
                );

                if (!value.empty())
                {
                    std::string normalized =
                        WideToUtf8(value);

                    constexpr std::string_view suffixes[] =
                    {
                        "/32",
                        "/255.255.255.255"
                    };

                    for (
                        const std::string_view suffix :
                        suffixes
                    )
                    {
                        if (normalized.ends_with(suffix))
                        {
                            normalized.resize(
                                normalized.size() -
                                suffix.size()
                            );

                            break;
                        }
                    }

                    addresses.insert(
                        std::move(normalized)
                    );
                }

                if (separator == std::wstring::npos)
                {
                    break;
                }

                start = separator + 1;
            }

            SysFreeString(rawAddresses);
        }

        rule->Release();
    }

    HRESULT ReadCurrentBlockedAddresses(
        std::unordered_set<std::string>& addresses,
        bool& rulesActive)
    {
        addresses.clear();
        rulesActive = false;

        INetFwRules* rules = nullptr;
        const HRESULT result = GetFirewallRules(&rules);

        if (FAILED(result))
        {
            return result;
        }

        std::unordered_set<std::string>
            outboundAddresses;

        std::unordered_set<std::string>
            inboundAddresses;

        bool outboundRuleActive = false;
        bool inboundRuleActive = false;

        AddAddressesFromRule(
            rules,
            ALL_OUTBOUND_RULE_NAME,
            NET_FW_RULE_DIR_OUT,
            outboundAddresses,
            outboundRuleActive
        );

        AddAddressesFromRule(
            rules,
            ALL_INBOUND_RULE_NAME,
            NET_FW_RULE_DIR_IN,
            inboundAddresses,
            inboundRuleActive
        );

        rules->Release();

        if (outboundRuleActive && inboundRuleActive)
        {
            for (
                const std::string& address :
                outboundAddresses
            )
            {
                if (inboundAddresses.contains(address))
                {
                    addresses.insert(address);
                }
            }
        }

        rulesActive = !addresses.empty();
        return S_OK;
    }

    std::wstring FormatHresult(HRESULT result)
    {
        wchar_t* systemMessage = nullptr;

        const DWORD characterCount = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            static_cast<DWORD>(result),
            0,
            reinterpret_cast<wchar_t*>(&systemMessage),
            0,
            nullptr
        );

        std::wstring message;

        if (characterCount != 0 && systemMessage)
        {
            message.assign(
                systemMessage,
                characterCount
            );

            LocalFree(systemMessage);
            message = Trim(message);
        }

        std::wstringstream stream;
        stream
            << L"0x"
            << std::uppercase
            << std::hex
            << std::setw(8)
            << std::setfill(L'0')
            << static_cast<unsigned long>(result);

        if (!message.empty())
        {
            return message + L" (" + stream.str() + L")";
        }

        return stream.str();
    }

    void ApplyFont(HWND control)
    {
        if (control && g_interfaceFont)
        {
            SendMessageW(
                control,
                WM_SETFONT,
                reinterpret_cast<WPARAM>(
                    g_interfaceFont
                ),
                TRUE
            );
        }
    }

    void ApplyControlTheme(HWND control)
    {
        if (control)
        {
            SetWindowTheme(
                control,
                g_whiteTheme
                    ? L"Explorer"
                    : L"DarkMode_Explorer",
                nullptr
            );
        }
    }

    void SetStatus(std::wstring_view text)
    {
        if (g_statusLabel)
        {
            SetWindowTextW(
                g_statusLabel,
                std::wstring(text).c_str()
            );
        }
    }

    std::size_t TotalServerCount()
    {
        std::size_t result = 0;

        for (const auto& pool : g_serverPools)
        {
            result += pool.servers.size();
        }

        return result;
    }

    std::size_t SelectedServerCount()
    {
        std::size_t result = 0;

        for (const auto& pool : g_serverPools)
        {
            result += static_cast<std::size_t>(
                std::count_if(
                    pool.servers.begin(),
                    pool.servers.end(),
                    [](const ServerEntry& server)
                    {
                        return server.selected;
                    }
                )
            );
        }

        return result;
    }

    std::vector<std::string> SelectedIpAddresses()
    {
        std::set<std::string> uniqueAddresses;

        for (const auto& pool : g_serverPools)
        {
            for (const auto& server : pool.servers)
            {
                if (server.selected)
                {
                    uniqueAddresses.insert(server.ip);
                }
            }
        }

        return {
            uniqueAddresses.begin(),
            uniqueAddresses.end()
        };
    }

    void MarkSelectionFromAddresses(
        const std::unordered_set<std::string>& addresses)
    {
        for (auto& pool : g_serverPools)
        {
            for (auto& server : pool.servers)
            {
                server.selected =
                    addresses.contains(server.ip);
            }
        }
    }

    void ClearAllSelections()
    {
        for (auto& pool : g_serverPools)
        {
            for (auto& server : pool.servers)
            {
                server.selected = false;
            }
        }
    }

    constexpr int TREE_STATE_UNCHECKED = 1;
    constexpr int TREE_STATE_CHECKED = 2;

    HBITMAP CreateTreeStateBitmap(
        HDC referenceDeviceContext,
        int size,
        int state)
    {
        HDC memoryDeviceContext =
            CreateCompatibleDC(referenceDeviceContext);

        if (!memoryDeviceContext)
        {
            return nullptr;
        }

        HBITMAP bitmap = CreateCompatibleBitmap(
            referenceDeviceContext,
            size,
            size
        );

        if (!bitmap)
        {
            DeleteDC(memoryDeviceContext);
            return nullptr;
        }

        HGDIOBJ previousBitmap = SelectObject(
            memoryDeviceContext,
            bitmap
        );

        RECT background{0, 0, size, size};
        HBRUSH backgroundBrush = CreateSolidBrush(
            WINDOW_BACKGROUND
        );

        FillRect(
            memoryDeviceContext,
            &background,
            backgroundBrush
        );

        DeleteObject(backgroundBrush);

        const int inset = 3;
        RECT checkbox{
            inset,
            inset,
            size - inset,
            size - inset
        };

        HBRUSH checkboxBrush = CreateSolidBrush(
            WINDOW_BACKGROUND
        );

        HPEN borderPen = CreatePen(
            PS_SOLID,
            1,
            ACCENT_RED
        );

        HGDIOBJ previousBrush = SelectObject(
            memoryDeviceContext,
            checkboxBrush
        );

        HGDIOBJ previousPen = SelectObject(
            memoryDeviceContext,
            borderPen
        );

        Rectangle(
            memoryDeviceContext,
            checkbox.left,
            checkbox.top,
            checkbox.right,
            checkbox.bottom
        );

        if (state == TREE_STATE_CHECKED)
        {
            HPEN checkPen = CreatePen(
                PS_SOLID,
                2,
                ACCENT_RED
            );

            SelectObject(memoryDeviceContext, checkPen);

            const POINT checkPoints[] =
            {
                {
                    checkbox.left + 3,
                    checkbox.top + 6
                },
                {
                    checkbox.left + 5,
                    checkbox.top + 9
                },
                {
                    checkbox.right - 3,
                    checkbox.top + 3
                }
            };

            Polyline(
                memoryDeviceContext,
                checkPoints,
                static_cast<int>(
                    std::size(checkPoints)
                )
            );

            SelectObject(memoryDeviceContext, borderPen);
            DeleteObject(checkPen);
        }
        SelectObject(memoryDeviceContext, previousPen);
        SelectObject(memoryDeviceContext, previousBrush);
        SelectObject(memoryDeviceContext, previousBitmap);

        DeleteObject(borderPen);
        DeleteObject(checkboxBrush);
        DeleteDC(memoryDeviceContext);
        return bitmap;
    }

    HIMAGELIST CreateTreeStateImageList(HWND tree)
    {
        constexpr int imageSize = 18;

        HIMAGELIST imageList = ImageList_Create(
            imageSize,
            imageSize,
            ILC_COLOR24,
            2,
            1
        );

        if (!imageList)
        {
            return nullptr;
        }

        HDC deviceContext = GetDC(tree);

        if (!deviceContext)
        {
            ImageList_Destroy(imageList);
            return nullptr;
        }

        for (
            int state = TREE_STATE_UNCHECKED;
            state <= TREE_STATE_CHECKED;
            ++state
        )
        {
            HBITMAP bitmap = CreateTreeStateBitmap(
                deviceContext,
                imageSize,
                state
            );

            if (!bitmap)
            {
                ReleaseDC(tree, deviceContext);
                ImageList_Destroy(imageList);
                return nullptr;
            }

            ImageList_Add(imageList, bitmap, nullptr);
            DeleteObject(bitmap);
        }

        ReleaseDC(tree, deviceContext);
        ImageList_SetBkColor(
            imageList,
            WINDOW_BACKGROUND
        );

        return imageList;
    }

    void SetTreeItemState(
        HTREEITEM item,
        int state)
    {
        if (!g_serverTree || !item)
        {
            return;
        }

        TVITEMW treeItem{};
        treeItem.mask =
            TVIF_HANDLE |
            TVIF_IMAGE |
            TVIF_SELECTEDIMAGE;
        treeItem.hItem = item;
        treeItem.iImage =
            state == TREE_STATE_CHECKED ? 1 : 0;
        treeItem.iSelectedImage =
            treeItem.iImage;
        TreeView_SetItem(g_serverTree, &treeItem);
    }

    TreeNodeData* GetTreeNodeData(HTREEITEM item)
    {
        if (!g_serverTree || !item)
        {
            return nullptr;
        }

        TVITEMW treeItem{};
        treeItem.mask = TVIF_HANDLE | TVIF_PARAM;
        treeItem.hItem = item;

        if (!TreeView_GetItem(g_serverTree, &treeItem))
        {
            return nullptr;
        }

        return reinterpret_cast<TreeNodeData*>(
            treeItem.lParam
        );
    }

    int GetPoolState(std::size_t poolIndex)
    {
        if (poolIndex >= g_serverPools.size())
        {
            return TREE_STATE_UNCHECKED;
        }

        const auto& servers =
            g_serverPools[poolIndex].servers;

        const bool allSelected =
            !servers.empty() &&
            std::all_of(
                servers.begin(),
                servers.end(),
                [](const ServerEntry& server)
                {
                    return server.selected;
                }
            );

        return allSelected
            ? TREE_STATE_CHECKED
            : TREE_STATE_UNCHECKED;
    }

    void RefreshPoolTreeState(std::size_t poolIndex)
    {
        if (poolIndex >= g_poolTreeItems.size())
        {
            return;
        }

        SetTreeItemState(
            g_poolTreeItems[poolIndex],
            GetPoolState(poolIndex)
        );
    }

    void RefreshAllTreeStates()
    {
        for (
            std::size_t poolIndex = 0;
            poolIndex < g_serverPools.size();
            ++poolIndex
        )
        {
            if (poolIndex < g_serverTreeItems.size())
            {
                const auto& items =
                    g_serverTreeItems[poolIndex];

                for (
                    std::size_t serverIndex = 0;
                    serverIndex <
                        g_serverPools[poolIndex].servers.size() &&
                    serverIndex < items.size();
                    ++serverIndex
                )
                {
                    SetTreeItemState(
                        items[serverIndex],
                        g_serverPools[poolIndex].
                            servers[serverIndex].
                            selected
                            ? TREE_STATE_CHECKED
                            : TREE_STATE_UNCHECKED
                    );
                }
            }

            RefreshPoolTreeState(poolIndex);
        }

        if (g_serverTree)
        {
            InvalidateRect(g_serverTree, nullptr, TRUE);
        }
    }

    HRESULT SynchronizeSelectionsFromFirewall()
    {
        std::unordered_set<std::string>
            blockedAddresses;

        bool rulesActive = false;

        const HRESULT result =
            ReadCurrentBlockedAddresses(
                blockedAddresses,
                rulesActive
            );

        if (FAILED(result))
        {
            return result;
        }

        g_firewallRulesActive = rulesActive;

        MarkSelectionFromAddresses(
            blockedAddresses
        );

        RefreshAllTreeStates();
        return S_OK;
    }

    void RecreateTreeStateImages()
    {
        if (!g_serverTree)
        {
            return;
        }

        HIMAGELIST newStateImages =
            CreateTreeStateImageList(g_serverTree);

        if (!newStateImages)
        {
            return;
        }

        HIMAGELIST oldStateImages =
            TreeView_SetImageList(
                g_serverTree,
                newStateImages,
                TVSIL_NORMAL
            );

        g_treeStateImages = newStateImages;

        if (
            oldStateImages &&
            oldStateImages != newStateImages
        )
        {
            ImageList_Destroy(oldStateImages);
        }

        RefreshAllTreeStates();
    }

    int GetAccentMenuCommand(AccentTheme theme)
    {
        switch (theme)
        {
            case AccentTheme::Green:
                return ID_ACCENT_GREEN;

            case AccentTheme::Orange:
                return ID_ACCENT_ORANGE;

            case AccentTheme::Purple:
                return ID_ACCENT_PURPLE;

            case AccentTheme::Pink:
                return ID_ACCENT_PINK;

            case AccentTheme::Blue:
                return ID_ACCENT_BLUE;

            case AccentTheme::Red:
            default:
                return ID_ACCENT_RED;
        }
    }

    void ApplyCurrentTheme()
    {
        RefreshThemePalette();

        HBRUSH newBackgroundBrush =
            CreateSolidBrush(WINDOW_BACKGROUND);

        if (newBackgroundBrush)
        {
            HBRUSH oldBackgroundBrush =
                g_backgroundBrush;

            g_backgroundBrush =
                newBackgroundBrush;

            if (g_mainWindow)
            {
                SetClassLongPtrW(
                    g_mainWindow,
                    GCLP_HBRBACKGROUND,
                    reinterpret_cast<LONG_PTR>(
                        g_backgroundBrush
                    )
                );
            }

            if (oldBackgroundBrush)
            {
                DeleteObject(oldBackgroundBrush);
            }
        }

        ApplyControlTheme(g_serverTree);
        ApplyControlTheme(g_statusLabel);
        ApplyControlTheme(g_authorLabel);
        ApplyControlTheme(g_blockButton);
        ApplyControlTheme(g_removeButton);
        ApplyControlTheme(g_themeButton);
        ApplyControlTheme(g_colorButton);

        if (g_serverTree)
        {
            TreeView_SetBkColor(
                g_serverTree,
                WINDOW_BACKGROUND
            );

            TreeView_SetTextColor(
                g_serverTree,
                WINDOW_TEXT
            );

            TreeView_SetLineColor(
                g_serverTree,
                CONTROL_BORDER
            );

            RecreateTreeStateImages();
        }

        UpdateCustomizationButtonText();
        ApplyWindowChromeTheme();

        if (g_mainWindow)
        {
            RedrawWindow(
                g_mainWindow,
                nullptr,
                nullptr,
                RDW_INVALIDATE |
                RDW_ERASE |
                RDW_ALLCHILDREN |
                RDW_UPDATENOW
            );
        }
    }

    void ShowAccentColorMenu()
    {
        if (!g_mainWindow || !g_colorButton)
        {
            return;
        }

        HMENU menu = CreatePopupMenu();

        if (!menu)
        {
            return;
        }

        AppendMenuW(
            menu,
            MF_STRING,
            ID_ACCENT_RED,
            L"RED"
        );

        AppendMenuW(
            menu,
            MF_STRING,
            ID_ACCENT_GREEN,
            L"GREEN"
        );

        AppendMenuW(
            menu,
            MF_STRING,
            ID_ACCENT_ORANGE,
            L"ORANGE"
        );

        AppendMenuW(
            menu,
            MF_STRING,
            ID_ACCENT_PURPLE,
            L"PURPLE"
        );

        AppendMenuW(
            menu,
            MF_STRING,
            ID_ACCENT_PINK,
            L"PINK"
        );

        AppendMenuW(
            menu,
            MF_STRING,
            ID_ACCENT_BLUE,
            L"SKY BLUE"
        );

        CheckMenuRadioItem(
            menu,
            ID_ACCENT_RED,
            ID_ACCENT_BLUE,
            GetAccentMenuCommand(g_accentTheme),
            MF_BYCOMMAND
        );

        RECT buttonRectangle{};
        GetWindowRect(
            g_colorButton,
            &buttonRectangle
        );

        SetForegroundWindow(g_mainWindow);

        const UINT command = TrackPopupMenuEx(
            menu,
            TPM_RIGHTALIGN |
            TPM_BOTTOMALIGN |
            TPM_LEFTBUTTON |
            TPM_RETURNCMD,
            buttonRectangle.right,
            buttonRectangle.top,
            g_mainWindow,
            nullptr
        );

        DestroyMenu(menu);
        PostMessageW(
            g_mainWindow,
            WM_NULL,
            0,
            0
        );

        switch (command)
        {
            case ID_ACCENT_RED:
                g_accentTheme = AccentTheme::Red;
                break;

            case ID_ACCENT_GREEN:
                g_accentTheme = AccentTheme::Green;
                break;

            case ID_ACCENT_ORANGE:
                g_accentTheme = AccentTheme::Orange;
                break;

            case ID_ACCENT_PURPLE:
                g_accentTheme = AccentTheme::Purple;
                break;

            case ID_ACCENT_PINK:
                g_accentTheme = AccentTheme::Pink;
                break;

            case ID_ACCENT_BLUE:
                g_accentTheme = AccentTheme::Blue;
                break;

            default:
                return;
        }

        SaveAppearanceSettings();
        ApplyCurrentTheme();
    }

    void BuildServerTree()
    {
        if (!g_serverTree)
        {
            return;
        }

        SendMessageW(
            g_serverTree,
            WM_SETREDRAW,
            FALSE,
            0
        );

        TreeView_DeleteAllItems(g_serverTree);
        g_treeNodes.clear();
        g_poolTreeItems.clear();
        g_serverTreeItems.clear();

        g_poolTreeItems.reserve(g_serverPools.size());
        g_serverTreeItems.resize(g_serverPools.size());

        for (
            std::size_t poolIndex = 0;
            poolIndex < g_serverPools.size();
            ++poolIndex
        )
        {
            const auto& pool = g_serverPools[poolIndex];

            auto poolData =
                std::make_unique<TreeNodeData>();

            poolData->poolIndex = poolIndex;
            poolData->isPool = true;

            TreeNodeData* poolDataPointer =
                poolData.get();

            g_treeNodes.push_back(
                std::move(poolData)
            );

            std::wstring poolName =
                Utf8ToWide(pool.name);

            TVINSERTSTRUCTW poolInsert{};
            poolInsert.hParent = TVI_ROOT;
            poolInsert.hInsertAfter = TVI_LAST;
            poolInsert.item.mask =
                TVIF_TEXT |
                TVIF_PARAM |
                TVIF_STATE |
                TVIF_IMAGE |
                TVIF_SELECTEDIMAGE;
            poolInsert.item.pszText = poolName.data();
            poolInsert.item.lParam =
                reinterpret_cast<LPARAM>(
                    poolDataPointer
                );
            poolInsert.item.stateMask =
                TVIS_EXPANDED;
            poolInsert.item.state =
                TVIS_EXPANDED;
            poolInsert.item.iImage =
                GetPoolState(poolIndex) ==
                    TREE_STATE_CHECKED
                    ? 1
                    : 0;
            poolInsert.item.iSelectedImage =
                poolInsert.item.iImage;

            HTREEITEM poolItem = TreeView_InsertItem(
                g_serverTree,
                &poolInsert
            );

            g_poolTreeItems.push_back(poolItem);

            auto& serverItems =
                g_serverTreeItems[poolIndex];

            serverItems.reserve(pool.servers.size());

            for (
                std::size_t serverIndex = 0;
                serverIndex < pool.servers.size();
                ++serverIndex
            )
            {
                const auto& server =
                    pool.servers[serverIndex];

                auto serverData =
                    std::make_unique<TreeNodeData>();

                serverData->poolIndex = poolIndex;
                serverData->serverIndex = serverIndex;
                serverData->isPool = false;

                TreeNodeData* serverDataPointer =
                    serverData.get();

                g_treeNodes.push_back(
                    std::move(serverData)
                );

                std::wstring serverLabel =
                    Utf8ToWide(server.name) +
                    L"    " +
                    Utf8ToWide(server.address);

                TVINSERTSTRUCTW serverInsert{};
                serverInsert.hParent = poolItem;
                serverInsert.hInsertAfter = TVI_LAST;
                serverInsert.item.mask =
                    TVIF_TEXT |
                    TVIF_PARAM |
                    TVIF_IMAGE |
                    TVIF_SELECTEDIMAGE;
                serverInsert.item.pszText =
                    serverLabel.data();
                serverInsert.item.lParam =
                    reinterpret_cast<LPARAM>(
                        serverDataPointer
                    );
                serverInsert.item.iImage =
                    server.selected ? 1 : 0;
                serverInsert.item.iSelectedImage =
                    serverInsert.item.iImage;

                serverItems.push_back(
                    TreeView_InsertItem(
                        g_serverTree,
                        &serverInsert
                    )
                );
            }

            TreeView_Expand(
                g_serverTree,
                poolItem,
                TVE_EXPAND
            );
        }

        SendMessageW(
            g_serverTree,
            WM_SETREDRAW,
            TRUE,
            0
        );

        InvalidateRect(g_serverTree, nullptr, TRUE);
    }

    void LayoutControls()
    {
        if (!g_mainWindow)
        {
            return;
        }

        RECT clientArea{};
        GetClientRect(g_mainWindow, &clientArea);

        const int width =
            clientArea.right - clientArea.left;

        const int height =
            clientArea.bottom - clientArea.top;

        const int statusTop = std::max(0, height - 102);
        const int buttonTop = std::max(0, height - 62);

        if (g_headerLabel)
        {
            MoveWindow(
                g_headerLabel,
                18,
                13,
                std::max(100, width - 236),
                28,
                TRUE
            );
        }

        if (g_authorLabel)
        {
            MoveWindow(
                g_authorLabel,
                std::max(18, width - 218),
                13,
                200,
                28,
                TRUE
            );
        }

        if (g_serverTree)
        {
            MoveWindow(
                g_serverTree,
                16,
                48,
                std::max(100, width - 32),
                std::max(100, height - 164),
                TRUE
            );
        }

        if (g_statusLabel)
        {
            MoveWindow(
                g_statusLabel,
                20,
                statusTop,
                std::max(100, width - 40),
                24,
                TRUE
            );
        }

        if (g_blockButton)
        {
            MoveWindow(
                g_blockButton,
                20,
                buttonTop,
                205,
                38,
                TRUE
            );
        }

        if (g_removeButton)
        {
            MoveWindow(
                g_removeButton,
                237,
                buttonTop,
                190,
                38,
                TRUE
            );
        }

        constexpr int colorButtonWidth = 180;
        constexpr int themeButtonWidth = 190;
        constexpr int customizationGap = 12;
        constexpr int rightMargin = 20;

        const int colorButtonLeft =
            std::max(
                20,
                width -
                    rightMargin -
                    colorButtonWidth
            );

        const int themeButtonLeft =
            std::max(
                20,
                colorButtonLeft -
                    customizationGap -
                    themeButtonWidth
            );

        if (g_themeButton)
        {
            MoveWindow(
                g_themeButton,
                themeButtonLeft,
                buttonTop,
                themeButtonWidth,
                38,
                TRUE
            );
        }

        if (g_colorButton)
        {
            MoveWindow(
                g_colorButton,
                colorButtonLeft,
                buttonTop,
                colorButtonWidth,
                38,
                TRUE
            );
        }
    }

    void SetSelectionChangedStatus()
    {
        const std::size_t selected =
            SelectedServerCount();

        SetStatus(
            L"Selected: " +
            std::to_wstring(selected) +
            L" of " +
            std::to_wstring(TotalServerCount()) +
            L". Click BLOCK SELECTED to apply the new selection."
        );
    }

    void ToggleTreeItem(HTREEITEM item)
    {
        TreeNodeData* node = GetTreeNodeData(item);

        if (
            !node ||
            node->poolIndex >= g_serverPools.size()
        )
        {
            return;
        }

        auto& pool =
            g_serverPools[node->poolIndex];

        if (node->isPool)
        {
            const bool selectAll =
                GetPoolState(node->poolIndex) !=
                TREE_STATE_CHECKED;

            for (
                std::size_t serverIndex = 0;
                serverIndex < pool.servers.size();
                ++serverIndex
            )
            {
                pool.servers[serverIndex].selected =
                    selectAll;

                if (
                    node->poolIndex <
                        g_serverTreeItems.size() &&
                    serverIndex <
                        g_serverTreeItems[
                            node->poolIndex
                        ].size()
                )
                {
                    SetTreeItemState(
                        g_serverTreeItems[
                            node->poolIndex
                        ][serverIndex],
                        selectAll
                            ? TREE_STATE_CHECKED
                            : TREE_STATE_UNCHECKED
                    );
                }
            }

            RefreshPoolTreeState(node->poolIndex);
        }
        else
        {
            if (node->serverIndex >= pool.servers.size())
            {
                return;
            }

            auto& server =
                pool.servers[node->serverIndex];

            server.selected = !server.selected;

            SetTreeItemState(
                item,
                server.selected
                    ? TREE_STATE_CHECKED
                    : TREE_STATE_UNCHECKED
            );

            RefreshPoolTreeState(node->poolIndex);
        }

        InvalidateRect(g_serverTree, nullptr, TRUE);
        SetSelectionChangedStatus();
    }

    void HandleTreeCheckboxClick()
    {
        if (!g_serverTree)
        {
            return;
        }

        POINT cursor{};
        GetCursorPos(&cursor);
        ScreenToClient(g_serverTree, &cursor);

        TVHITTESTINFO hitTest{};
        hitTest.pt = cursor;

        TreeView_HitTest(g_serverTree, &hitTest);

        if (
            hitTest.hItem &&
            (hitTest.flags & TVHT_ONITEMICON) != 0
        )
        {
            ToggleTreeItem(hitTest.hItem);
        }
    }

    LRESULT HandleTreeCustomDraw(
        NMTVCUSTOMDRAW* customDraw)
    {
        if (!customDraw)
        {
            return CDRF_DODEFAULT;
        }

        if (
            customDraw->nmcd.dwDrawStage ==
            CDDS_PREPAINT
        )
        {
            return CDRF_NOTIFYITEMDRAW;
        }

        if (
            customDraw->nmcd.dwDrawStage ==
            CDDS_ITEMPREPAINT
        )
        {
            const bool selected =
                (customDraw->nmcd.uItemState &
                 CDIS_SELECTED) != 0;

            auto* node =
                reinterpret_cast<TreeNodeData*>(
                    customDraw->nmcd.lItemlParam
                );

            customDraw->clrTextBk =
                selected
                    ? ACCENT_RED_DARK
                    : WINDOW_BACKGROUND;

            customDraw->clrText =
                selected
                    ? WINDOW_TEXT
                    : (
                        node && node->isPool
                            ? ACCENT_RED
                            : WINDOW_TEXT
                    );

            if (
                node &&
                node->isPool &&
                g_groupFont
            )
            {
                SelectObject(
                    customDraw->nmcd.hdc,
                    g_groupFont
                );
            }
            else if (g_interfaceFont)
            {
                SelectObject(
                    customDraw->nmcd.hdc,
                    g_interfaceFont
                );
            }

            return CDRF_NEWFONT;
        }

        return CDRF_DODEFAULT;
    }

    void DrawOwnerDrawButton(
        const DRAWITEMSTRUCT* drawItem)
    {
        if (!drawItem)
        {
            return;
        }

        const bool pressed =
            (drawItem->itemState & ODS_SELECTED) != 0;

        const bool disabled =
            (drawItem->itemState & ODS_DISABLED) != 0;

        const bool hot =
            (drawItem->itemState & ODS_HOTLIGHT) != 0;

        const COLORREF fillColor =
            pressed
                ? ACCENT_RED
                : (
                    hot
                        ? ACCENT_RED_HOVER
                        : WINDOW_BACKGROUND
                );

        HBRUSH fillBrush = CreateSolidBrush(fillColor);
        FillRect(
            drawItem->hDC,
            &drawItem->rcItem,
            fillBrush
        );
        DeleteObject(fillBrush);

        HBRUSH borderBrush = CreateSolidBrush(
            disabled
                ? CONTROL_BORDER
                : ACCENT_RED
        );

        RECT border = drawItem->rcItem;
        FrameRect(
            drawItem->hDC,
            &border,
            borderBrush
        );
        InflateRect(&border, -1, -1);
        FrameRect(
            drawItem->hDC,
            &border,
            borderBrush
        );
        DeleteObject(borderBrush);

        wchar_t text[256]{};
        GetWindowTextW(
            drawItem->hwndItem,
            text,
            static_cast<int>(std::size(text))
        );

        SetBkMode(drawItem->hDC, TRANSPARENT);
        SetTextColor(
            drawItem->hDC,
            disabled
                ? MUTED_TEXT
                : (
                    pressed || hot
                        ? GetContrastingTextColor(
                            fillColor
                        )
                        : ACCENT_RED
                )
        );

        if (g_buttonFont)
        {
            SelectObject(
                drawItem->hDC,
                g_buttonFont
            );
        }

        RECT textArea = drawItem->rcItem;
        DrawTextW(
            drawItem->hDC,
            text,
            -1,
            &textArea,
            DT_CENTER |
            DT_VCENTER |
            DT_SINGLELINE |
            DT_NOPREFIX
        );

        if (
            (drawItem->itemState & ODS_FOCUS) != 0
        )
        {
            RECT focus = drawItem->rcItem;
            InflateRect(&focus, -4, -4);
            DrawFocusRect(drawItem->hDC, &focus);
        }
    }

    void HandleBlockSelected()
    {
        const std::vector<std::string> addresses =
            SelectedIpAddresses();

        if (addresses.empty())
        {
            MessageBoxW(
                g_mainWindow,
                L"Select at least one server before applying "
                L"the block.",
                L"Nothing selected",
                MB_OK | MB_ICONINFORMATION
            );

            return;
        }

        SetStatus(L"Applying Windows Firewall rules...");

        const HRESULT result =
            ApplyFirewallRules(addresses);

        if (FAILED(result))
        {
            if (
                FAILED(
                    SynchronizeSelectionsFromFirewall()
                )
            )
            {
                g_firewallRulesActive = false;
                ClearAllSelections();
                RefreshAllTreeStates();
            }

            const std::wstring error =
                L"Unable to apply the Windows Firewall rules.\n\n"
                L"Stage: " +
                (
                    g_firewallOperationStage.empty()
                    ? std::wstring(L"Unknown")
                    : g_firewallOperationStage
                ) +
                L"\n\n" +
                FormatHresult(result);

            SetStatus(
                L"Failed to apply Windows Firewall rules."
            );

            MessageBoxW(
                g_mainWindow,
                error.c_str(),
                L"Firewall error",
                MB_OK | MB_ICONERROR
            );

            return;
        }

        g_firewallRulesActive = true;

        SynchronizeSelectionsFromFirewall();

        const std::size_t terminatedTcpConnections =
            TerminateTcpConnections(addresses);

        SetStatus(
            L"Blocked " +
            std::to_wstring(addresses.size()) +
            L" IP addresses: all protocols, ports and directions. Closed " +
            std::to_wstring(terminatedTcpConnections) +
            L" existing TCP connections. UDP packets are now dropped."
        );
    }

    void HandleRemoveBlocks()
    {
        SetStatus(L"Removing Windows Firewall rules...");

        const HRESULT result = RemoveFirewallRules();

        if (FAILED(result))
        {
            const std::wstring error =
                L"Unable to remove the Windows Firewall rules.\n\n" +
                FormatHresult(result);

            SetStatus(
                L"Failed to remove Windows Firewall rules."
            );

            MessageBoxW(
                g_mainWindow,
                error.c_str(),
                L"Firewall error",
                MB_OK | MB_ICONERROR
            );

            return;
        }

        g_firewallRulesActive = false;
        ClearAllSelections();
        RefreshAllTreeStates();

        SetStatus(
            L"All firewall rules created by this program "
            L"were removed."
        );
    }

    LRESULT CALLBACK WindowProcedure(
        _In_ HWND window,
        _In_ UINT message,
        _In_ WPARAM wParam,
        _In_ LPARAM lParam)
    {
        switch (message)
        {
            case WM_CREATE:
            {
                g_mainWindow = window;

                const wchar_t* interfaceFontName =
                    g_orbitronLoaded
                        ? L"Orbitron"
                        : L"Segoe UI";

                g_interfaceFont = CreateFontW(
                    -18,
                    0,
                    0,
                    0,
                    FW_NORMAL,
                    FALSE,
                    FALSE,
                    FALSE,
                    DEFAULT_CHARSET,
                    OUT_DEFAULT_PRECIS,
                    CLIP_DEFAULT_PRECIS,
                    CLEARTYPE_QUALITY,
                    DEFAULT_PITCH | FF_DONTCARE,
                    interfaceFontName
                );

                g_groupFont = CreateFontW(
                    -18,
                    0,
                    0,
                    0,
                    FW_SEMIBOLD,
                    FALSE,
                    FALSE,
                    FALSE,
                    DEFAULT_CHARSET,
                    OUT_DEFAULT_PRECIS,
                    CLIP_DEFAULT_PRECIS,
                    CLEARTYPE_QUALITY,
                    DEFAULT_PITCH | FF_DONTCARE,
                    interfaceFontName
                );

                g_buttonFont = CreateFontW(
                    -15,
                    0,
                    0,
                    0,
                    FW_SEMIBOLD,
                    FALSE,
                    FALSE,
                    FALSE,
                    DEFAULT_CHARSET,
                    OUT_DEFAULT_PRECIS,
                    CLIP_DEFAULT_PRECIS,
                    CLEARTYPE_QUALITY,
                    DEFAULT_PITCH | FF_DONTCARE,
                    interfaceFontName
                );

                g_headerLabel = CreateWindowExW(
                    0,
                    L"STATIC",
                    L"SERVER TREE",
                    WS_CHILD |
                    WS_VISIBLE |
                    SS_LEFT |
                    SS_CENTERIMAGE,
                    0,
                    0,
                    0,
                    0,
                    window,
                    nullptr,
                    nullptr,
                    nullptr
                );

                g_authorLabel = CreateWindowExW(
                    0,
                    L"STATIC",
                    L"by.Kwokwiy",
                    WS_CHILD |
                    WS_VISIBLE |
                    SS_RIGHT |
                    SS_CENTERIMAGE,
                    0,
                    0,
                    0,
                    0,
                    window,
                    nullptr,
                    nullptr,
                    nullptr
                );

                g_serverTree = CreateWindowExW(
                    0,
                    WC_TREEVIEWW,
                    L"",
                    WS_CHILD |
                    WS_VISIBLE |
                    WS_TABSTOP |
                    WS_VSCROLL |
                    TVS_HASBUTTONS |
                    TVS_HASLINES |
                    TVS_LINESATROOT |
                    TVS_SHOWSELALWAYS |
                    TVS_FULLROWSELECT,
                    0,
                    0,
                    0,
                    0,
                    window,
                    reinterpret_cast<HMENU>(
                        static_cast<INT_PTR>(
                            ID_SERVER_TREE
                        )
                    ),
                    nullptr,
                    nullptr
                );

                if (!g_serverTree)
                {
                    return -1;
                }

                ApplyFont(g_headerLabel);
                ApplyFont(g_authorLabel);
                ApplyFont(g_serverTree);
                ApplyControlTheme(g_serverTree);

                if (g_headerLabel && g_groupFont)
                {
                    SendMessageW(
                        g_headerLabel,
                        WM_SETFONT,
                        reinterpret_cast<WPARAM>(
                            g_groupFont
                        ),
                        TRUE
                    );
                }

                if (g_authorLabel && g_buttonFont)
                {
                    SendMessageW(
                        g_authorLabel,
                        WM_SETFONT,
                        reinterpret_cast<WPARAM>(
                            g_buttonFont
                        ),
                        TRUE
                    );
                }

                TreeView_SetBkColor(
                    g_serverTree,
                    WINDOW_BACKGROUND
                );

                TreeView_SetTextColor(
                    g_serverTree,
                    WINDOW_TEXT
                );

                TreeView_SetLineColor(
                    g_serverTree,
                    CONTROL_BORDER
                );

                TreeView_SetIndent(g_serverTree, 24);

                SendMessageW(
                    g_serverTree,
                    TVM_SETITEMHEIGHT,
                    25,
                    0
                );

                g_treeStateImages =
                    CreateTreeStateImageList(
                        g_serverTree
                    );

                if (g_treeStateImages)
                {
                    TreeView_SetImageList(
                        g_serverTree,
                        g_treeStateImages,
                        TVSIL_NORMAL
                    );
                }

                g_statusLabel = CreateWindowExW(
                    0,
                    L"STATIC",
                    g_initialStatus.c_str(),
                    WS_CHILD | WS_VISIBLE | SS_LEFT,
                    0,
                    0,
                    0,
                    0,
                    window,
                    nullptr,
                    nullptr,
                    nullptr
                );

                g_blockButton = CreateWindowExW(
                    0,
                    L"BUTTON",
                    L"BLOCK SELECTED",
                    WS_CHILD |
                    WS_VISIBLE |
                    WS_TABSTOP |
                    BS_OWNERDRAW,
                    0,
                    0,
                    0,
                    0,
                    window,
                    reinterpret_cast<HMENU>(
                        static_cast<INT_PTR>(
                            ID_BLOCK_SELECTED
                        )
                    ),
                    nullptr,
                    nullptr
                );

                g_removeButton = CreateWindowExW(
                    0,
                    L"BUTTON",
                    L"REMOVE BLOCKS",
                    WS_CHILD |
                    WS_VISIBLE |
                    WS_TABSTOP |
                    BS_OWNERDRAW,
                    0,
                    0,
                    0,
                    0,
                    window,
                    reinterpret_cast<HMENU>(
                        static_cast<INT_PTR>(
                            ID_REMOVE_BLOCKS
                        )
                    ),
                    nullptr,
                    nullptr
                );

                g_themeButton = CreateWindowExW(
                    0,
                    L"BUTTON",
                    L"WHITE THEME: OFF",
                    WS_CHILD |
                    WS_VISIBLE |
                    WS_TABSTOP |
                    BS_OWNERDRAW,
                    0,
                    0,
                    0,
                    0,
                    window,
                    reinterpret_cast<HMENU>(
                        static_cast<INT_PTR>(
                            ID_TOGGLE_WHITE_THEME
                        )
                    ),
                    nullptr,
                    nullptr
                );

                g_colorButton = CreateWindowExW(
                    0,
                    L"BUTTON",
                    L"COLOR: RED",
                    WS_CHILD |
                    WS_VISIBLE |
                    WS_TABSTOP |
                    BS_OWNERDRAW,
                    0,
                    0,
                    0,
                    0,
                    window,
                    reinterpret_cast<HMENU>(
                        static_cast<INT_PTR>(
                            ID_ACCENT_COLOR
                        )
                    ),
                    nullptr,
                    nullptr
                );

                ApplyFont(g_statusLabel);
                ApplyFont(g_blockButton);
                ApplyFont(g_removeButton);
                ApplyFont(g_themeButton);
                ApplyFont(g_colorButton);

                if (g_buttonFont)
                {
                    SendMessageW(
                        g_blockButton,
                        WM_SETFONT,
                        reinterpret_cast<WPARAM>(
                            g_buttonFont
                        ),
                        TRUE
                    );

                    SendMessageW(
                        g_removeButton,
                        WM_SETFONT,
                        reinterpret_cast<WPARAM>(
                            g_buttonFont
                        ),
                        TRUE
                    );

                    SendMessageW(
                        g_themeButton,
                        WM_SETFONT,
                        reinterpret_cast<WPARAM>(
                            g_buttonFont
                        ),
                        TRUE
                    );

                    SendMessageW(
                        g_colorButton,
                        WM_SETFONT,
                        reinterpret_cast<WPARAM>(
                            g_buttonFont
                        ),
                        TRUE
                    );
                }

                ApplyControlTheme(g_statusLabel);
                ApplyControlTheme(g_authorLabel);
                ApplyControlTheme(g_blockButton);
                ApplyControlTheme(g_removeButton);
                ApplyControlTheme(g_themeButton);
                ApplyControlTheme(g_colorButton);

                UpdateCustomizationButtonText();
                BuildServerTree();
                LayoutControls();
                return 0;
            }

            case WM_SIZE:
                LayoutControls();
                return 0;

            case WM_GETMINMAXINFO:
            {
                auto* sizeInfo =
                    reinterpret_cast<MINMAXINFO*>(
                        lParam
                    );

                sizeInfo->ptMinTrackSize.x = 900;
                sizeInfo->ptMinTrackSize.y = 680;
                return 0;
            }

            case WM_NOTIFY:
            {
                auto* notification =
                    reinterpret_cast<NMHDR*>(
                        lParam
                    );

                if (
                    notification &&
                    notification->idFrom ==
                        ID_SERVER_TREE
                )
                {
                    if (
                        notification->code ==
                        NM_CUSTOMDRAW
                    )
                    {
                        return HandleTreeCustomDraw(
                            reinterpret_cast<
                                NMTVCUSTOMDRAW*
                            >(lParam)
                        );
                    }

                    if (
                        notification->code ==
                        NM_CLICK
                    )
                    {
                        HandleTreeCheckboxClick();
                        return 0;
                    }

                    if (
                        notification->code ==
                        TVN_KEYDOWN
                    )
                    {
                        const auto* keyNotification =
                            reinterpret_cast<
                                NMTVKEYDOWN*
                            >(lParam);

                        if (
                            keyNotification->wVKey ==
                            VK_SPACE
                        )
                        {
                            ToggleTreeItem(
                                TreeView_GetSelection(
                                    g_serverTree
                                )
                            );

                            return 1;
                        }
                    }
                }

                return 0;
            }

            case WM_DRAWITEM:
            {
                const auto* drawItem =
                    reinterpret_cast<DRAWITEMSTRUCT*>(
                        lParam
                    );

                if (
                    drawItem &&
                    (
                        drawItem->CtlID ==
                            ID_BLOCK_SELECTED ||
                        drawItem->CtlID ==
                            ID_REMOVE_BLOCKS ||
                        drawItem->CtlID ==
                            ID_TOGGLE_WHITE_THEME ||
                        drawItem->CtlID ==
                            ID_ACCENT_COLOR
                    )
                )
                {
                    DrawOwnerDrawButton(drawItem);
                    return TRUE;
                }

                break;
            }

            case WM_COMMAND:
            {
                if (HIWORD(wParam) != BN_CLICKED)
                {
                    break;
                }

                const int controlId =
                    LOWORD(wParam);

                if (controlId == ID_BLOCK_SELECTED)
                {
                    HandleBlockSelected();
                    return 0;
                }

                if (controlId == ID_REMOVE_BLOCKS)
                {
                    HandleRemoveBlocks();
                    return 0;
                }

                if (
                    controlId ==
                    ID_TOGGLE_WHITE_THEME
                )
                {
                    g_whiteTheme = !g_whiteTheme;
                    SaveAppearanceSettings();
                    ApplyCurrentTheme();
                    return 0;
                }

                if (controlId == ID_ACCENT_COLOR)
                {
                    ShowAccentColorMenu();
                    return 0;
                }

                break;
            }

            case WM_CTLCOLORSTATIC:
            case WM_CTLCOLORBTN:
            {
                HDC deviceContext =
                    reinterpret_cast<HDC>(wParam);

                SetTextColor(
                    deviceContext,
                    message == WM_CTLCOLORSTATIC
                        ? ACCENT_RED
                        : ACCENT_RED
                );

                SetBkColor(
                    deviceContext,
                    WINDOW_BACKGROUND
                );

                SetBkMode(
                    deviceContext,
                    TRANSPARENT
                );

                return reinterpret_cast<LRESULT>(
                    g_backgroundBrush
                );
            }

            case WM_ERASEBKGND:
            {
                RECT clientArea{};
                GetClientRect(window, &clientArea);
                FillRect(
                    reinterpret_cast<HDC>(wParam),
                    &clientArea,
                    g_backgroundBrush
                );
                return 1;
            }

            case WM_PAINT:
            {
                PAINTSTRUCT paint{};
                HDC deviceContext =
                    BeginPaint(window, &paint);

                RECT clientArea{};
                GetClientRect(window, &clientArea);

                FillRect(
                    deviceContext,
                    &clientArea,
                    g_backgroundBrush
                );

                EndPaint(window, &paint);
                return 0;
            }

            case WM_DESTROY:
                if (
                    g_serverTree &&
                    g_treeStateImages
                )
                {
                    TreeView_SetImageList(
                        g_serverTree,
                        nullptr,
                        TVSIL_NORMAL
                    );

                    ImageList_Destroy(
                        g_treeStateImages
                    );

                    g_treeStateImages = nullptr;
                }

                g_treeNodes.clear();
                g_poolTreeItems.clear();
                g_serverTreeItems.clear();
                PostQuitMessage(0);
                return 0;
        }

        return DefWindowProcW(
            window,
            message,
            wParam,
            lParam
        );
    }
}

int WINAPI wWinMain(
    _In_ HINSTANCE instance,
    _In_opt_ HINSTANCE,
    _In_ PWSTR,
    _In_ int showCommand)
{
    if (!IsRunningAsAdministrator())
    {
        if (!RelaunchAsAdministrator())
        {
            MessageBoxW(
                nullptr,
                L"Administrator rights are required to manage "
                L"system-wide Windows Firewall rules.",
                L"Administrator rights required",
                MB_OK | MB_ICONERROR
            );
        }

        return 0;
    }

    const HRESULT comResult = CoInitializeEx(
        nullptr,
        COINIT_APARTMENTTHREADED
    );

    if (FAILED(comResult))
    {
        MessageBoxW(
            nullptr,
            FormatHresult(comResult).c_str(),
            L"COM initialization failed",
            MB_OK | MB_ICONERROR
        );

        return 1;
    }

    std::filesystem::path loadedJsonPath;
    std::string loadError;

    if (
        !LoadServers(
            g_serverPools,
            loadedJsonPath,
            loadError
        )
    )
    {
        MessageBoxW(
            nullptr,
            Utf8ToWide(loadError).c_str(),
            L"Servers.json error",
            MB_OK | MB_ICONERROR
        );

        CoUninitialize();
        return 1;
    }

    const HRESULT firewallReadResult =
        SynchronizeSelectionsFromFirewall();

    if (FAILED(firewallReadResult))
    {
        g_firewallRulesActive = false;
        ClearAllSelections();
    }

    if (g_firewallRulesActive)
    {
        g_initialStatus =
            L"FIREWALL RULES ACTIVE";
    }
    else
    {
        g_initialStatus.clear();
    }

    INITCOMMONCONTROLSEX commonControls{};
    commonControls.dwSize = sizeof(commonControls);
    commonControls.dwICC = ICC_TREEVIEW_CLASSES |
                           ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&commonControls);

    SetProcessDpiAwarenessContext(
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
    );

    LoadAppearanceSettings();
    RefreshThemePalette();

    g_backgroundBrush = CreateSolidBrush(
        WINDOW_BACKGROUND
    );

    const int largeIconWidth =
        GetSystemMetrics(SM_CXICON);
    const int largeIconHeight =
        GetSystemMetrics(SM_CYICON);
    const int smallIconWidth =
        GetSystemMetrics(SM_CXSMICON);
    const int smallIconHeight =
        GetSystemMetrics(SM_CYSMICON);

    g_largeExternalIcon = LoadExternalApplicationIcon(
        largeIconWidth,
        largeIconHeight
    );

    g_smallExternalIcon = LoadExternalApplicationIcon(
        smallIconWidth,
        smallIconHeight
    );

    HICON embeddedLargeIcon =
        LoadEmbeddedApplicationIcon(
            instance,
            largeIconWidth,
            largeIconHeight
        );

    HICON embeddedSmallIcon =
        LoadEmbeddedApplicationIcon(
            instance,
            smallIconWidth,
            smallIconHeight
        );

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.style = CS_HREDRAW | CS_VREDRAW;
    windowClass.lpfnWndProc = WindowProcedure;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(
        nullptr,
        IDC_ARROW
    );
    windowClass.hIcon =
        g_largeExternalIcon
        ? g_largeExternalIcon
        : (
            embeddedLargeIcon
            ? embeddedLargeIcon
            : LoadIconW(nullptr, IDI_APPLICATION)
        );
    windowClass.hIconSm =
        g_smallExternalIcon
        ? g_smallExternalIcon
        : (
            embeddedSmallIcon
            ? embeddedSmallIcon
            : LoadIconW(nullptr, IDI_APPLICATION)
        );
    windowClass.hbrBackground = g_backgroundBrush;
    windowClass.lpszClassName = WINDOW_CLASS_NAME;

    if (!RegisterClassExW(&windowClass))
    {
        MessageBoxW(
            nullptr,
            L"Unable to register the window class.",
            L"Window error",
            MB_OK | MB_ICONERROR
        );

        DeleteObject(g_backgroundBrush);
        UnloadExternalApplicationIcons();
        CoUninitialize();
        return 1;
    }

    LoadOrbitronFonts();

    HWND window = CreateWindowExW(
        0,
        WINDOW_CLASS_NAME,
        L"StalzoneServerBlocker",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        1080,
        760,
        nullptr,
        nullptr,
        instance,
        nullptr
    );

    if (!window)
    {
        MessageBoxW(
            nullptr,
            L"Unable to create the main window.",
            L"Window error",
            MB_OK | MB_ICONERROR
        );

        UnregisterClassW(
            WINDOW_CLASS_NAME,
            instance
        );

        DeleteObject(g_backgroundBrush);
        UnloadExternalApplicationIcons();
        UnloadOrbitronFonts();
        CoUninitialize();
        return 1;
    }

    ApplyWindowChromeTheme();

    ShowWindow(window, showCommand);
    UpdateWindow(window);

    MSG message{};
    int exitCode = 0;

    while (true)
    {
        const BOOL messageResult = GetMessageW(
            &message,
            nullptr,
            0,
            0
        );

        if (messageResult == -1)
        {
            exitCode = 1;
            break;
        }

        if (messageResult == 0)
        {
            exitCode = static_cast<int>(
                message.wParam
            );

            break;
        }

        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    if (g_interfaceFont)
    {
        DeleteObject(g_interfaceFont);
        g_interfaceFont = nullptr;
    }

    if (g_groupFont)
    {
        DeleteObject(g_groupFont);
        g_groupFont = nullptr;
    }

    if (g_buttonFont)
    {
        DeleteObject(g_buttonFont);
        g_buttonFont = nullptr;
    }

    UnloadOrbitronFonts();

    UnregisterClassW(
        WINDOW_CLASS_NAME,
        instance
    );

    if (g_backgroundBrush)
    {
        DeleteObject(g_backgroundBrush);
        g_backgroundBrush = nullptr;
    }

    UnloadExternalApplicationIcons();

    CoUninitialize();
    return exitCode;
}
