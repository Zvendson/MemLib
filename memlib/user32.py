"""
:platform: Windows

.. note:: Learn how to `Create a GUI <https://learn.microsoft.com/en-us/windows/win32/learnwin32/creating-a-window>`_

"""

from ctypes import POINTER, byref, windll
from ctypes.wintypes import ATOM, BOOL, DWORD, HANDLE, HWND, INT, LONG, LPARAM, LPCSTR, LPCWSTR, LPVOID, UINT, WPARAM

from memlib.structs import MSG, WNDCLASS



def CreateWindowExA(
        exStyle: int,
        className: bytes,
        windowName: bytes,
        style: int,
        x: int,
        y: int,
        width: int,
        height: int,
        wndParent: int,
        menuHandle: int,
        instanceHandle: int,
        param: int) -> int:
    """
    Creates an overlapped, pop-up, or child window with an extended window style; otherwise, this function is identical
    to the CreateWindow function. For more information about creating a window and for full descriptions of the other
    parameters of CreateWindowEx, see CreateWindow.

    **See also:** `RegisterClassA
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerclassa>`_

    :param exStyle: The extended window style of the window being created.
    :param className: A null-terminated string or a class atom created by a previous call
                      to the RegisterClass or RegisterClassEx function.
    :param windowName: The window name.
    :param style: The style of the window being created.
    :param x: The initial horizontal position of the window.
    :param y: The initial vertical position of the window.
    :param width: The width, in device units, of the window.
    :param height: The height, in device units, of the window.
    :param wndParent: A handle to the parent or owner window of the window being created.
    :param menuHandle: A handle to a menu, or specifies a child-window identifier, depending on the window style.
    :param instanceHandle: A handle to the instance of the module to be associated with the window.
    :param param: Pointer to a value to be passed to the window through the CREATESTRUCT pointed to by the lParam
                  param of the WM_CREATE message.
    :return: If the function succeeds, the return value is a handle to the new window. If the function fails, the return
             value is 0. To get extended error information, call GetLastError.
    """

    return _CreateWindowExA(
        exStyle,
        className,
        windowName,
        style,
        x,
        y,
        width,
        height,
        wndParent,
        menuHandle,
        instanceHandle,
        param
    )

def DestroyWindow(windowHandle: int) -> bool:
    """
    Destroys the specified window.

    :param windowHandle: A handle to the window to be destroyed.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero.
              To get extended error information, call GetLastError.
    """

    return _DestroyWindow(windowHandle)

def RegisterClassA(wndClass: WNDCLASS) -> int:
    """
    Registers a window class for subsequent use in calls to the CreateWindow or CreateWindowEx function.

    **See also:** `RegisterClassA
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerclassa>`_


    :param wndClass: A pointer to a WNDCLASS structure.
    :returns: If the function succeeds, the return value is a class atom that uniquely identifies the class being
              registered. If the function fails, the return value is zero. To get extended error information, call
              GetLastError.
    """

    return _RegisterClassA(byref(wndClass))


def GetMessageA(msg: POINTER(MSG), windowHandle: int, msgFilterMin: int, msgFilterMax: int) -> bool:
    """
    Retrieves a message from the calling thread's message queue. The function dispatches incoming sent messages until
    a posted message is available for retrieval. Unlike GetMessage, the PeekMessage function does not wait for a
    message to be posted before returning.

    **See also:** `GetMessageA
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagea>`_

    :param msg: A pointer to a MSG structure that receives message information from the thread's message queue.
    :param windowHandle: A handle to the window whose messages are to be retrieved.
                         The window must belong to the current thread.
    :param msgFilterMin: The integer value of the lowest message value to be retrieved.
    :param msgFilterMax: The integer value of the highest message value to be retrieved.
    :return: If the function retrieves a message other than WM_QUIT, the return value is nonzero. If the function
             retrieves the WM_QUIT message, the return value is zero. If there is an error, the return value is -1.
    """

    return _GetMessageA(msg, windowHandle, msgFilterMin, msgFilterMax)


def TranslateMessage(lpMsg: POINTER(MSG)) -> bool:
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


def DispatchMessageA(msg: POINTER(MSG)) -> int:
    """
    Dispatches a message to a window procedure. It is typically used to dispatch a message retrieved by the GetMessage
    function.

    **See also:** `DispatchMessageA
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-dispatchmessagea>`_

    :param msg: A pointer to a MSG structure that contains the message.
    :returns: The return value specifies the value returned by the window procedure. Although its meaning depends on the
              message being dispatched, the return value generally is ignored.
    """

    return _DispatchMessageA(msg)


def PostQuitMessage(exitCode: int) -> None:
    """
    Indicates to the system that a thread has made a request to terminate (quit). It is typically used in response to a
    WM_DESTROY message.

    **See also:** `PostQuitMessage
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postquitmessage>`_

    :param exitCode: The application exit code. This value is used as the wParam parameter of the WM_QUIT message.
    """

    _PostQuitMessage(exitCode)


def PostMessageA(windowHandle: int, msg: int, wParam: int, lParam: int) -> bool:
    """
    Places (posts) a message in the message queue associated with the thread that created the specified window and
    returns without waiting for the thread to process the message. To post a message in the message queue associated
    with a thread, use the PostThreadMessage function.

    **See also:** `PostMessageA <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagea>`_

    :param windowHandle: A handle to the window whose window procedure is to receive the message.
    :param msg: The message to be posted.
    :param wParam: Additional message-specific information.
    :param lParam: Additional message-specific information.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero.
              To get extended error information, call GetLastError.
    """

    return _PostMessageA(windowHandle, msg, wParam, lParam)


def SendMessageA(windowHandle: int, msg: int, wParam: int, lParam: int) -> bool:
    """
    Sends the specified message to a window or windows. The SendMessage function calls the window procedure for the
    specified window and does not return until the window procedure has processed the message.

    **See also:** `SendMessageA <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagea>`_

    :param windowHandle: A handle to the window whose window procedure is to receive the message.
    :param msg: The message to be posted.
    :param wParam: Additional message-specific information.
    :param lParam: Additional message-specific information.
    :returns: The return value specifies the result of the message processing; it depends on the message sent.
    """

    return _SendMessageA(windowHandle, msg, wParam, lParam)


def DefWindowProcA(windowHandle: int, msg: int, wParam: int, lParam: int) -> int:
    """
    Calls the default window procedure to provide default processing for any window messages that an application does
    not process. This function ensures that every message is processed. DefWindowProc is called with the same parameters
    received by the window procedure.

    **See also:** `DefWindowProcA
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-defwindowproca>`_

    :param windowHandle: A handle to the window procedure that received the message.
    :param msg: The message.
    :param wParam: Additional message information. The content of this parameter depends on the value of the Msg
                   parameter.
    :param lParam: Additional message information. The content of this parameter depends on the value of the Msg
                   parameter.
    :return: The return value is the result of the message processing and depends on the message.
    """

    return _DefWindowProcA(windowHandle, msg, wParam, lParam)



def MessageBoxW(hwindowHandlend: int, text: str, caption: str, typeFlags: int) -> int:
    """
    Displays a modal dialog box that contains a system icon, a set of buttons, and a brief application-specific message,
    such as status or error information. The message box returns an integer value that indicates which button the user
    clicked.

    **See also:** `MessageBoxW
    <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw>`_

    :param hwindowHandlend: A handle to the owner window of the message box to be created. If this parameter is NULL, the message
                 box has no owner window.
    :param text: The message to be displayed. If the string consists of more than one line, you can separate the lines
                 using a carriage return and/or linefeed character between each line.
    :param caption: The dialog box title. If this parameter is NULL, the default title is Error.
    :param typeFlags: The contents and behavior of the dialog box.
    :returns: If a message box has a Cancel button, the function returns the IDCANCEL value if either the ESC key is
              pressed or the Cancel button is selected. If the message box has no Cancel button, pressing ESC will no
              effect - unless an MB_OK button is present. If an MB_OK button is displayed and the user presses ESC, the
              return value will be IDOK. If the function fails, the return value is zero. To get extended error
              information, call GetLastError. If the function succeeds, the return value is one of the following
              menu-item `values
              <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw#return-value>`_
    """

    return _MessageBoxW(hwindowHandlend, text, caption, typeFlags)


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
