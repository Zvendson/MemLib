"""
:platform: Windows

.. note:: Learn how to `Create a GUI <https://learn.microsoft.com/en-us/windows/win32/learnwin32/creating-a-window>`_

"""

from ctypes import POINTER, byref, windll
from ctypes.wintypes import ATOM, BOOL, DWORD, HANDLE, HWND, INT, LONG, LPARAM, LPCSTR, LPCWSTR, LPVOID, UINT, WPARAM

import memlib.structs


def CreateWindowExA(dwExStyle: int, lpClassName: bytes, lpWindowName: bytes,
                   dwStyle: int, X: int, Y: int, nWidth: int, nHeight: int,
                   hWndParent: int, hMenu: int, hInstance: int, lpParam: int) -> int:
    """
    Creates an overlapped, pop-up, or child window with an extended window style; otherwise, this function is identical
    to the CreateWindow function. For more information about creating a window and for full descriptions of the other
    parameters of CreateWindowEx, see CreateWindow.

    **See also:** `RegisterClassA
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerclassa>`_

    :param dwExStyle: The extended window style of the window being created.
    :param lpClassName: A null-terminated string or a class atom created by a previous call
                        to the RegisterClass or RegisterClassEx function.
    :param lpWindowName: The window name.
    :param dwStyle: The style of the window being created.
    :param X: The initial horizontal position of the window.
    :param Y: The initial vertical position of the window.
    :param nWidth: The width, in device units, of the window.
    :param nHeight: The height, in device units, of the window.
    :param hWndParent: A handle to the parent or owner window of the window being created.
    :param hMenu: A handle to a menu, or specifies a child-window identifier, depending on the window style.
    :param hInstance: A handle to the instance of the module to be associated with the window.
    :param lpParam: Pointer to a value to be passed to the window through the CREATESTRUCT pointed to by the lParam
                    param of the WM_CREATE message.
    :return: If the function succeeds, the return value is a handle to the new window. If the function fails, the return
             value is 0. To get extended error information, call GetLastError.
    """

    return _CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y,
                nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam)

def DestroyWindow(hWnd: int) -> bool:
    """
    Destroys the specified window.

    :param hWnd: A handle to the window to be destroyed.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero.
              To get extended error information, call GetLastError.
    """

    return _DestroyWindow(hWnd)

def RegisterClassA(lpWndClass: memlib.structs.WNDCLASS) -> int:
    """
    Registers a window class for subsequent use in calls to the CreateWindow or CreateWindowEx function.

    **See also:** `RegisterClassA
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerclassa>`_


    :param lpWndClass: A pointer to a WNDCLASS structure.
    :returns: If the function succeeds, the return value is a class atom that uniquely identifies the class being
              registered. If the function fails, the return value is zero. To get extended error information, call
              GetLastError.
    """

    return _RegisterClassA(byref(lpWndClass))


def GetMessageA(lpMsg: POINTER(memlib.structs.MSG), hWnd: int, wMsgFilterMin: int, wMsgFilterMax: int) -> bool:
    """
    Retrieves a message from the calling thread's message queue. The function dispatches incoming sent messages until
    a posted message is available for retrieval. Unlike GetMessage, the PeekMessage function does not wait for a
    message to be posted before returning.

    **See also:** `GetMessageA
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagea>`_

    :param lpMsg: A pointer to a MSG structure that receives message information from the thread's message queue.
    :param hWnd: A handle to the window whose messages are to be retrieved.
                 The window must belong to the current thread.
    :param wMsgFilterMin: The integer value of the lowest message value to be retrieved.
    :param wMsgFilterMax: The integer value of the highest message value to be retrieved.
    :return: If the function retrieves a message other than WM_QUIT, the return value is nonzero. If the function
             retrieves the WM_QUIT message, the return value is zero. If there is an error, the return value is -1.
    """

    return _GetMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax)


def TranslateMessage(lpMsg: POINTER(memlib.structs.MSG)) -> bool:
    """
    Translates virtual-key messages into character messages. The character messages are posted to the calling thread's
    message queue, to be read the next time the thread calls the GetMessage or PeekMessage function.

    **See also:** `TranslateMessage
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-translatemessage>`_

    :param lpMsg: A pointer to a MSG structure that contains message information retrieved from the calling thread's
                  message queue by using the GetMessage or PeekMessage function.
    :returns: True if the message is translated, False otherwise.
    """

    return _TranslateMessage(lpMsg)


def DispatchMessageA(lpMsg: POINTER(memlib.structs.MSG)) -> int:
    """
    Dispatches a message to a window procedure. It is typically used to dispatch a message retrieved by the GetMessage
    function.

    **See also:** `DispatchMessageA
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-dispatchmessagea>`_

    :param lpMsg: A pointer to a MSG structure that contains the message.
    :returns: The return value specifies the value returned by the window procedure. Although its meaning depends on the
              message being dispatched, the return value generally is ignored.
    """

    return _DispatchMessageA(lpMsg)


def PostQuitMessage(nExitCode: int) -> None:
    """
    Indicates to the system that a thread has made a request to terminate (quit). It is typically used in response to a
    WM_DESTROY message.

    **See also:** `PostQuitMessage
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postquitmessage>`_

    :param nExitCode: The application exit code. This value is used as the wParam parameter of the WM_QUIT message.
    """

    _PostQuitMessage(nExitCode)


def PostMessageA(hWnd: int, Msg: int, wParam: int, lParam: int) -> bool:
    """
    Places (posts) a message in the message queue associated with the thread that created the specified window and
    returns without waiting for the thread to process the message. To post a message in the message queue associated
    with a thread, use the PostThreadMessage function.

    **See also:** `PostMessageA <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagea>`_

    :param hWnd: A handle to the window whose window procedure is to receive the message.
    :param Msg: The message to be posted.
    :param wParam: Additional message-specific information.
    :param lParam: Additional message-specific information.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero.
              To get extended error information, call GetLastError.
    """

    return _PostMessageA(hWnd, Msg, wParam, lParam)


def SendMessageA(hWnd: int, Msg: int, wParam: int, lParam: int) -> bool:
    """
    Sends the specified message to a window or windows. The SendMessage function calls the window procedure for the
    specified window and does not return until the window procedure has processed the message.

    **See also:** `SendMessageA <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagea>`_

    :param hWnd: A handle to the window whose window procedure is to receive the message.
    :param Msg: The message to be posted.
    :param wParam: Additional message-specific information.
    :param lParam: Additional message-specific information.
    :returns: The return value specifies the result of the message processing; it depends on the message sent.
    """

    return _SendMessageA(hWnd, Msg, wParam, lParam)


def DefWindowProcA(hWnd: int, Msg: int, wParam: int, lParam: int) -> int:
    """
    Calls the default window procedure to provide default processing for any window messages that an application does
    not process. This function ensures that every message is processed. DefWindowProc is called with the same parameters
    received by the window procedure.

    **See also:** `DefWindowProcA
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-defwindowproca>`_

    :param hWnd: A handle to the window procedure that received the message.
    :param Msg: The message.
    :param wParam: Additional message information. The content of this parameter depends on the value of the Msg
                   parameter.
    :param lParam: Additional message information. The content of this parameter depends on the value of the Msg
                   parameter.
    :return: The return value is the result of the message processing and depends on the message.
    """

    return _DefWindowProcA(hWnd, Msg, wParam, lParam)



def MessageBoxW(hWnd: int, text: str, caption: str, uType: int) -> int:
    """
    Displays a modal dialog box that contains a system icon, a set of buttons, and a brief application-specific message,
    such as status or error information. The message box returns an integer value that indicates which button the user
    clicked.

    **See also:** `MessageBoxW
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw>`_

    :param hWnd: A handle to the owner window of the message box to be created. If this parameter is NULL, the message
                 box has no owner window.
    :param text: The message to be displayed. If the string consists of more than one line, you can separate the lines
                 using a carriage return and/or linefeed character between each line.
    :param caption: The dialog box title. If this parameter is NULL, the default title is Error.
    :param uType: The contents and behavior of the dialog box.
    :returns: If a message box has a Cancel button, the function returns the IDCANCEL value if either the ESC key is
              pressed or the Cancel button is selected. If the message box has no Cancel button, pressing ESC will no
              effect - unless an MB_OK button is present. If an MB_OK button is displayed and the user presses ESC, the
              return value will be IDOK. If the function fails, the return value is zero. To get extended error
              information, call GetLastError. If the function succeeds, the return value is one of the following
              menu-item `values
              <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw#return-value>`_
    """

    return _MessageBoxW(hWnd, text, caption, uType)


# region Function bindings
_CreateWindowExA = windll.user32.CreateWindowExA
_CreateWindowExA.argtypes = [DWORD, LPCSTR, LPCSTR, DWORD, INT, INT, INT, INT, HWND, INT, INT, INT]
_CreateWindowExA.restype = HWND

_DestroyWindow = windll.user32.DestroyWindow
_DestroyWindow.argtypes = [HWND]
_DestroyWindow.restype = BOOL

_RegisterClassA = windll.user32.RegisterClassA
_RegisterClassA.argtypes = [HANDLE]
_RegisterClassA.restype = ATOM

_GetMessageA = windll.user32.GetMessageA
_GetMessageA.argtypes = [LPVOID, HWND, WPARAM, LPARAM]
_GetMessageA.restype = BOOL

_TranslateMessage = windll.user32.TranslateMessage
_TranslateMessage.argtypes = [LPVOID]
_TranslateMessage.restype = BOOL

_DispatchMessageA = windll.user32.DispatchMessageA
_DispatchMessageA.argtypes = [LPVOID]
_DispatchMessageA.restype = LONG

_PostQuitMessage = windll.user32.PostQuitMessage
_PostQuitMessage.argtypes = [INT]
_PostQuitMessage.restype = None

_PostMessageA = windll.user32.PostMessageA
_PostMessageA.argtypes = [HWND, UINT, WPARAM, LPARAM]
_PostMessageA.restype = LONG

_SendMessageA = windll.user32.SendMessageA
_SendMessageA.argtypes = [HWND, UINT, WPARAM, LPARAM]
_SendMessageA.restype = LONG

_DefWindowProcA = windll.user32.DefWindowProcA
_DefWindowProcA.argtypes = [HWND, UINT, WPARAM, LPARAM]
_DefWindowProcA.restype = LONG

_MessageBoxW = windll.user32.MessageBoxW
_MessageBoxW.argtypes = [HWND, LPCWSTR, LPCWSTR, UINT]
_MessageBoxW.restype = INT
# endregion
