// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __STOUT_OS_WINDOWS_FILEDESCRIPTOR__
#define __STOUT_OS_WINDOWS_FILEDESCRIPTOR__
#include <memory>
#include <array>
#include <windows.h>

#include <WinSock2.h>

namespace os {

class Translator;

// Function to validate if a SOCKET or an int is
// indeed a socket.
bool is_socket(SOCKET fd);

class WindowsFileDescriptor {
  std::shared_ptr<Translator> adapter;
  HANDLE handle;
  SOCKET socket;
  int crtFd;

public:
  bool isSocket() const { return socket != INVALID_SOCKET; }
  bool isHandle() const { return handle != INVALID_HANDLE_VALUE; }
  bool isFile() const { return crtFd != -1; }

  WindowsFileDescriptor() {
    handle = INVALID_HANDLE_VALUE;
    socket = INVALID_SOCKET;
    crtFd = -1;
  }

  WindowsFileDescriptor(HANDLE h) : handle(h), crtFd(-1) {
    if (handle != INVALID_HANDLE_VALUE) {
      crtFd = _open_osfhandle(reinterpret_cast<intptr_t>(handle), O_RDWR);
      CHECK_NE(crtFd, -1);
    }
    socket = INVALID_SOCKET;
  }

  WindowsFileDescriptor(SOCKET s) : socket(s) {
    CHECK(is_socket(socket));
    handle = INVALID_HANDLE_VALUE;
    crtFd = -1;
  }

  WindowsFileDescriptor(int file) : crtFd(file) {
    handle = (HANDLE)::_get_osfhandle(file);
    CHECK(!is_socket(crtFd));
    socket = INVALID_SOCKET;
  }

  WindowsFileDescriptor(const WindowsFileDescriptor&) = default;
  WindowsFileDescriptor& operator=(const WindowsFileDescriptor&) = default;

  void addReference(std::shared_ptr<Translator> ref) { adapter = ref; }

  WindowsFileDescriptor& operator=(int file) {
    handle = INVALID_HANDLE_VALUE;
    socket = INVALID_SOCKET;
    crtFd = file;
    CHECK(!is_socket(crtFd));
    return *this;
  }

  WindowsFileDescriptor& operator=(SOCKET s) {
    handle = INVALID_HANDLE_VALUE;
    socket = s;
    crtFd = -1;
    CHECK(is_socket(socket));
    return *this;
  }

  void close() {
    if (isSocket()) {
      ::shutdown(socket, SD_BOTH);
      ::closesocket(socket);
      socket = INVALID_SOCKET;
    } else if (crtFd != -1) {
      ::_close(crtFd);
    } else if (handle != INVALID_HANDLE_VALUE) {
      CloseHandle(handle);
    }
  }

  operator SOCKET() const { return socket; }

  operator HANDLE() const { return handle; }

  operator int() const {
    // There is code that threats eveything as int
    if (isSocket()) {
      return static_cast<int>(socket);
    }
    return crtFd;
  }
};

constexpr int BUFSIZE = 4096;
enum SOCKETMODE { READ, WRITE };

class Translator {
  HANDLE Read = INVALID_HANDLE_VALUE;
  HANDLE Write = INVALID_HANDLE_VALUE;
  SOCKET PrivateSocket = INVALID_SOCKET;
  SOCKET ClientSocket = INVALID_SOCKET;
  PTP_WORK transferFunction = nullptr;

  SOCKETMODE direction;

public:
  Translator(SOCKETMODE dir) : direction(dir) {
    SECURITY_ATTRIBUTES saAttr;

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = nullptr;
    CHECK(CreatePipe(&Read, &Write, &saAttr, 0));

    // Disable internal side of the pipe.
    CHECK(SetHandleInformation(dir == READ ? Read : Write, HANDLE_FLAG_INHERIT,
                               0));

    struct addrinfo* result = nullptr, *ptr = nullptr, hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the local address and port to be used by the server
    CHECK_EQ(::getaddrinfo("localhost", 0, &hints, &result), 0);

    SOCKET ListenSocket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK_NE(ListenSocket, INVALID_SOCKET);

    // Setup the TCP listening socket
    if (::bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen) ==
        SOCKET_ERROR) {
      LOG(ERROR) << "Bind failed with error: " << WSAGetLastError();
      ::closesocket(ListenSocket);
    }

    ::freeaddrinfo(result);

    if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
      LOG(ERROR) << "Listen failed with error:" << WSAGetLastError();
      ::closesocket(ListenSocket);
    }

    PrivateSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK_NE(PrivateSocket, INVALID_SOCKET);

    struct sockaddr_in connect_addr;
    int size = sizeof(sockaddr_in);

    if (::getsockname(ListenSocket, (struct sockaddr*)&connect_addr, &size) ==
        -1) {
      LOG(ERROR) << "getsockname failed with error:" << WSAGetLastError();
    }

    if (connect(PrivateSocket, (struct sockaddr*)&connect_addr, size) ==
        SOCKET_ERROR) {
      LOG(ERROR) << "Connect failed with error:" << WSAGetLastError();
    };

    // Accept a client socket
    ClientSocket = accept(ListenSocket, nullptr, nullptr);
    CHECK_NE(ClientSocket, INVALID_SOCKET);

    ::closesocket(ListenSocket);

    transferFunction = CreateThreadpoolWork(TransferFunction, this, nullptr);
    SubmitThreadpoolWork(transferFunction);
  }

  ~Translator() {
    ::closesocket(PrivateSocket);
    ::CloseHandle(direction == READ ? Read : Write);
    WaitForThreadpoolWorkCallbacks(transferFunction, TRUE);
    CloseThreadpoolWork(transferFunction);
  }

  WindowsFileDescriptor reader() {
    if (direction == WRITE) {
      // If the socket is used to write the pipe is used to read.
      return WindowsFileDescriptor(Read);
    } else {
      return WindowsFileDescriptor(ClientSocket);
    }
  }

  WindowsFileDescriptor writer() {
    if (direction == WRITE) {
      // If the socket is used to write the pipe is used to read.
      return WindowsFileDescriptor(ClientSocket);
    } else {
      return WindowsFileDescriptor(Write);
    }
  }

private:
  static VOID CALLBACK TransferFunction(_Inout_ PTP_CALLBACK_INSTANCE Instance,
                                        _Inout_opt_ PVOID Context,
                                        _Inout_ PTP_WORK Work) {
    Translator* object = static_cast<Translator*>(Context);
    if (object->direction == WRITE) {
      object->ReadFromSocket();
    } else {
      object->ReadFromPipe();
    }
  }

  void ReadFromSocket() {
    for (;;) {
      char chBuf[BUFSIZE];
      DWORD bufferProcessed = 0;
      DWORD bytesSent = 0;
      int length = recv(PrivateSocket, chBuf, BUFSIZE, 0);
      if (length == -1) {
        // Socket error. Send EOF on the pipe.
        CloseHandle(Write);
        return;
      }
      if (length == 0) {
        // The socket has been closed. Exit the transfer loop
        CloseHandle(Write);
        return;
      }
      BOOL result = WriteFile(Write, chBuf, length, &bytesSent, nullptr);
      CHECK_NE(result, FALSE);
    }
  }

  void ReadFromPipe() {
    for (;;) {
      char chBuf[BUFSIZE];
      DWORD bufferProcessed = 0;
      DWORD bytesSent = 0;
      BOOL res = ReadFile(Read, chBuf, BUFSIZE, &bufferProcessed, nullptr);
      if (res != FALSE) {
        if (bufferProcessed == 0) {
          break;
        }
        ::send(PrivateSocket, (chBuf), bufferProcessed, 0);
      } else {
        DWORD err = GetLastError();
        switch (err) {
          case ERROR_NO_DATA:
            ::shutdown(PrivateSocket, SD_SEND);
            ::closesocket(PrivateSocket);
            return;
          case ERROR_PIPE_NOT_CONNECTED:
            SwitchToThread();
            continue;
          case ERROR_MORE_DATA:
            ::send(PrivateSocket, (chBuf), bufferProcessed, 0);
            continue;
          case ERROR_BROKEN_PIPE:
            ::shutdown(PrivateSocket, SD_SEND);
            ::closesocket(PrivateSocket);
            return;
        }
      }
    }
  }
};

inline bool is_socket(SOCKET fd) {
  int value = 0;
  int length = sizeof(int);

  if (::getsockopt(fd, SOL_SOCKET, SO_TYPE, (char*)&value, &length) ==
      SOCKET_ERROR) {
    switch (WSAGetLastError()) {
      case WSAENOTSOCK:
        return false;
      default:
        // TODO(benh): Handle `WSANOTINITIALISED`.
        return true;
    }
  }

  return true;
}

inline WindowsFileDescriptor dup(const WindowsFileDescriptor& f) {
  if (f.isSocket()) {
    WSAPROTOCOL_INFO protInfo;
    if (WSADuplicateSocket(f, GetCurrentProcessId(), &protInfo) !=
        INVALID_SOCKET) {
      SOCKET s = WSASocket(0, 0, 0, &protInfo, 0, 0);
      return s;
    };
    return INVALID_SOCKET;
  } else if (f.isFile()) {
    return ::dup(f.operator int());
  } else {
    return INVALID_HANDLE_VALUE;
  }
}

inline std::ostream& operator<<(std::ostream& stream,
                                const os::WindowsFileDescriptor& fd) {
  if (fd.isSocket()) {
    stream << fd.operator SOCKET();
  } else if (fd.isHandle()) {
    stream << fd.operator HANDLE();
  } else {
    stream << fd.operator int();
  }
  return stream;
}

inline std::istream& operator>>(std::istream& stream,
                                os::WindowsFileDescriptor& fd) {
  HANDLE handle;
  if (!(stream >> handle)) {
    stream.setstate(std::ios_base::badbit);
    return stream;
  }
  fd = os::WindowsFileDescriptor(handle);

  return stream;
}

inline bool operator==(const os::WindowsFileDescriptor& left, int right) {
  return (left.isSocket() && left.operator SOCKET() == right) ||
         (left.isFile() && left.operator int() == right);
}

inline bool operator<(const os::WindowsFileDescriptor& left,
                      const os::WindowsFileDescriptor& right) {
  return (left.isSocket() &&
          left.operator SOCKET() < right.operator SOCKET()) ||
         (left.isHandle() &&
          left.operator HANDLE() < right.operator HANDLE()) ||
         (left.isFile() && left.operator int() < right.operator int());
}

inline bool operator<(const os::WindowsFileDescriptor& left, const int& right) {
  return (left.isSocket() && left.operator SOCKET() < right) ||
         (left.isFile() && left.operator int() < right);
}

inline int MakePipe(std::array<os::WindowsFileDescriptor, 2>& pipes,
                    os::SOCKETMODE dir = os::SOCKETMODE::READ) {
  std::shared_ptr<os::Translator> adapter =
      std::make_shared<os::Translator>(dir);
  WindowsFileDescriptor reader = adapter->reader();
  WindowsFileDescriptor writer = adapter->writer();
  reader.addReference(adapter);
  writer.addReference(adapter);
  pipes[0] = reader;
  pipes[1] = writer;

  return 0;
}

} // namespace os {

#endif  // __STOUT_OS_WINDOWS_FILEDESCRIPTOR__
