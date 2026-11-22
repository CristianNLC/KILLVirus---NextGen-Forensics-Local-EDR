import os
import ctypes
from ctypes import wintypes

# Constantes de CryptoAPI / WinTrust
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_REVOKE_WHOLECHAIN = 1
WTD_CHOICE_FILE = 1
WTD_STATEACTION_IGNORE = 0

# dwProvFlags
WTD_REVOCATION_CHECK_CHAIN = 0x00000040
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000

ERROR_SUCCESS = 0
TRUST_E_NOSIGNATURE = 0x800B0100

_STATUS_NAMES = {
    TRUST_E_NOSIGNATURE: "Sin firma Authenticode embebida (puede estar firmado por catálogo)",
    0x800B0101: "Certificado expirado",
    0x800B0109: "Raíz no confiable",
    0x800B010A: "Cadena de certificados incompleta",
    0x800B010C: "Certificado revocado",
    0x800B010E: "No se pudo comprobar la revocación",
    0x800B0111: "Firma explícitamente no confiable",
    0x800B0001: "Proveedor de confianza desconocido",
    0x800B0003: "Formato de firma desconocido",
    0x800B0004: "Sujeto no confiable",
    0x80096010: "El contenido no coincide con la firma (manipulado)",
    0x80092026: "Restricción de seguridad criptográfica",
}


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]


# WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (wintypes.BYTE * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(GUID)),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", wintypes.LPVOID),
        ("pSIPClientData", wintypes.LPVOID),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", wintypes.LPVOID),
    ]


def verify_file_signature(filepath):
    """
    Verifica la firma Authenticode *embebida* de un binario.

    Comprueba cadena completa y revocación (WTD_REVOKE_WHOLECHAIN). Si no hay
    red, la comprobación de revocación puede fallar: en ese caso se devuelve
    False (fail-safe), nunca True.

    Limitación conocida: muchos binarios de Windows están firmados por catálogo
    (.cat) y no llevan firma embebida, por lo que WinVerifyTrust con
    WTD_CHOICE_FILE devuelve TRUST_E_NOSIGNATURE. Al ser un chequeo fail-safe,
    esos archivos se tratan como "no firmados" y nunca se usan para indultar
    una detección fuerte (hash/YARA); solo evitan reportar heurísticas débiles
    de binarios con firma embebida válida.

    Retorna: (is_signed: bool, status_message: str)
    """
    if not os.path.isfile(filepath):
        return False, "Archivo no encontrado"

    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = os.path.abspath(filepath)
    file_info.hFile = None
    file_info.pgKnownSubject = None

    trust_data = WINTRUST_DATA()
    trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    trust_data.pPolicyCallbackData = None
    trust_data.pSIPClientData = None
    trust_data.dwUIChoice = WTD_UI_NONE
    trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN
    trust_data.dwUnionChoice = WTD_CHOICE_FILE
    trust_data.pFile = ctypes.pointer(file_info)
    trust_data.dwStateAction = WTD_STATEACTION_IGNORE
    trust_data.hWVTStateData = None
    trust_data.pwszURLReference = None
    # Cadena + revocación online. Se permite red porque solo se llama cuando
    # ya existe una detección y queremos descartar falsos positivos.
    trust_data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN
    trust_data.dwUIContext = 0
    trust_data.pSignatureSettings = None

    try:
        wintrust = ctypes.windll.wintrust
        status = wintrust.WinVerifyTrust(
            None,
            ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(trust_data),
        )

        if status == ERROR_SUCCESS:
            return True, "Firma digital válida y de confianza"

        code = status & 0xFFFFFFFF
        reason = _STATUS_NAMES.get(code, "Firma inválida o no confiable")
        return False, f"{reason} (código {hex(code)})"
    except Exception as e:
        return False, f"Error al validar firma: {e}"
