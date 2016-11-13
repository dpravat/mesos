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

#include <stout/nothing.hpp>
#include <stout/unreachable.hpp>
#include <stout/try.hpp>

namespace os {

class Translator;

// Function to validate if a SOCKET or an int is
// indeed a socket.
bool is_socket(SOCKET fd);

class WindowsFD {
  std::shared_ptr<Translator> adapter;
  union {
    // We keep both a CRT FD as well as a `HANDLE`
    // regardless of whether we were constructed
    // from a file or a handle.
    //
    // This is because once we request for a CRT FD
    // from a `HANDLE`, we're required to close it
    // via `_close`. If we were to do the conversion
    // lazily upon request, the resulting CRT FD
    // would be dangling.
    struct {
      int file;
      HANDLE handle;
    };
    SOCKET socket;
  };
  bool nonblock = false;
  bool closed = false;

public:
  enum Type { FD_NONE, FD_FILE, FD_HANDLE, FD_SOCKET } type = FD_NONE;

  bool isSocket() const { return type == FD_SOCKET; }
  bool isHandle() const { return type == FD_HANDLE; }
  bool isFile() const { return (type == FD_FILE) | (type == FD_HANDLE); }

  WindowsFD() = default;

  ~WindowsFD() = default;

  WindowsFD(HANDLE h)
    : type(FD_HANDLE),
    file(
      h == INVALID_HANDLE_VALUE
      ? -1
      : _open_osfhandle(reinterpret_cast<intptr_t>(h), O_RDWR)),
    handle(h) {}

  WindowsFD(SOCKET s)
    : type(FD_SOCKET), socket(s) {
    CHECK(is_socket(socket));
  }

  WindowsFD(int file)
    : type(FD_FILE), handle(
      file < 0
      ? INVALID_HANDLE_VALUE
      : reinterpret_cast<HANDLE>(::_get_osfhandle(file))),
    file(file) {}

  WindowsFD(const WindowsFD&) = default;
  WindowsFD& operator=(const WindowsFD&) = default;
  void addReference(std::shared_ptr<Translator> ref) { adapter = ref; }
  std::shared_ptr<Translator> getReference() const { return adapter; }

  friend Try<Nothing> close(const WindowsFD& fd);
  friend bool operator==(const WindowsFD&, const WindowsFD&);
  friend bool operator==(const WindowsFD&, int);
  friend bool operator<(const WindowsFD&, const WindowsFD&);
  friend bool operator<(const WindowsFD&, int);
  friend std::ostream& operator<<(std::ostream& stream, const WindowsFD& fd);

  int crt() const { return file; }
  operator SOCKET() const { return socket; }

  operator HANDLE() const { return handle; }

  // libevent impropely defines a socket as intptr_t
  operator intptr_t() const {
    CHECK(isSocket());
    return static_cast<intptr_t>(socket);
  }

  explicit operator int() const {
    CHECK(isFile());
    return file;
  }
  Type type_() const { return type; }
};


inline std::ostream& operator<<(std::ostream& stream, const os::WindowsFD& fd) {
  CHECK_NE(fd.type, WindowsFD::FD_NONE);
  switch (fd.type) {
    case WindowsFD::FD_FILE: {
      stream << fd.operator int();
      break;
    }
    case WindowsFD::FD_HANDLE: {
      stream << fd.operator HANDLE();
      break;
    }
    case WindowsFD::FD_SOCKET: {
      stream << fd.operator SOCKET();
    }
  }
  return stream;
}


inline std::istream& operator>>(std::istream& stream, os::WindowsFD& fd) {
  HANDLE handle;
  if (!(stream >> handle)) {
    stream.setstate(std::ios_base::badbit);
    return stream;
  }
  fd = os::WindowsFD(handle);

  return stream;
}


inline bool operator==(const os::WindowsFD& left, const os::WindowsFD& right) {
  if (left.type != right.type) return false;
  switch (left.type) {
    case WindowsFD::FD_FILE: {
      return static_cast<int>(left) == static_cast<int>(right);
    }
    case WindowsFD::FD_HANDLE: {
      return static_cast<HANDLE>(left) == static_cast<HANDLE>(right);
    }
    case WindowsFD::FD_SOCKET: {
      return static_cast<SOCKET>(left) == static_cast<SOCKET>(right);
    }
  }
}


inline bool operator==(const os::WindowsFD& left, int right) {
  CHECK_NE(left.type, WindowsFD::FD_NONE);
  switch (left.type) {
    case WindowsFD::FD_FILE:
    case WindowsFD::FD_HANDLE: {
      return static_cast<int>(left) == right;
    }
    case WindowsFD::FD_SOCKET: {
      return static_cast<SOCKET>(left) == right;
    }
  }
}


inline bool operator<(const os::WindowsFD& left, const os::WindowsFD& right) {
  CHECK_NE(left.type, WindowsFD::FD_NONE);
  switch (left.type) {
    case WindowsFD::FD_FILE: {
      return static_cast<int>(left) < static_cast<int>(right);
    }
    case WindowsFD::FD_HANDLE: {
      return static_cast<HANDLE>(left) < static_cast<HANDLE>(right);
    }
    case WindowsFD::FD_SOCKET: {
      return static_cast<SOCKET>(left) < static_cast<SOCKET>(right);
    }
  }
}


inline bool operator<(const os::WindowsFD& left, int right) {
  CHECK_NE(left.type, WindowsFD::FD_NONE);
  switch (left.type) {
    case WindowsFD::FD_FILE:
    case WindowsFD::FD_HANDLE: {
      return static_cast<int>(left) < right;
    }
    case WindowsFD::FD_SOCKET: {
      return static_cast<SOCKET>(left) < right;
    }
  }
}


inline bool operator>=(const os::WindowsFD& left, const int& right) {
  return !(left < right);
}


constexpr int BUFSIZE = 4096;
enum SOCKETMODE { NONE, READ, WRITE };

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
    // No need to close the internal socket or the internal handle
    // They are closed olready at this time
    WaitForThreadpoolWorkCallbacks(transferFunction, TRUE);
    CloseThreadpoolWork(transferFunction);
  }

  WindowsFD reader() {
    if (direction == WRITE) {
      // If the socket is used to write the pipe is used to read.
      return WindowsFD(Read);
    } else {
      return WindowsFD(ClientSocket);
    }
  }

  WindowsFD writer() {
    if (direction == WRITE) {
      // If the socket is used to write the pipe is used to read.
      return WindowsFD(ClientSocket);
    } else {
      return WindowsFD(Write);
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


inline WindowsFD dup(const WindowsFD& f) {
  if (f.isSocket()) {
    WSAPROTOCOL_INFO protInfo;
    if (WSADuplicateSocket(f, GetCurrentProcessId(), &protInfo) !=
        INVALID_SOCKET) {
      SOCKET s = WSASocket(0, 0, 0, &protInfo, 0, 0);
      WindowsFD ret = s;
      ret.addReference(f.getReference());
      return ret;
    };
    return INVALID_SOCKET;
  } else if (f.isFile()) {
    WindowsFD ret = ::dup(f.operator int());
    ret.addReference(f.getReference());
    return ret;
  } else {
    return INVALID_HANDLE_VALUE;
  }
}


inline Try<Nothing> std_pipe(os::WindowsFD pipes[2]) {
  // Create inheritable pipe, as described in MSDN[1].
  //
  // [1] https://msdn.microsoft.com/en-us/library/windows/desktop/aa365782(v=vs.85).aspx
  SECURITY_ATTRIBUTES securityAttr;
  securityAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
  securityAttr.bInheritHandle = TRUE;
  securityAttr.lpSecurityDescriptor = nullptr;

  HANDLE read_handle;
  HANDLE write_handle;

  const BOOL result = ::CreatePipe(
    &read_handle,
    &write_handle,
    &securityAttr,
    0);
  if (result == 0) {
    return WindowsError();
  }
  pipes[0] = read_handle;
  pipes[1] = write_handle;

  return Nothing();
}


inline Try<Nothing> pipe(os::WindowsFD pipes[2],
                    os::SOCKETMODE dir = os::SOCKETMODE::NONE) {
  if (dir == os::SOCKETMODE::NONE) {
    return std_pipe(pipes);
  } else {
    std::shared_ptr<os::Translator> adapter =
        std::make_shared<os::Translator>(dir);
    WindowsFD reader = adapter->reader();
    WindowsFD writer = adapter->writer();
    reader.addReference(adapter);
    writer.addReference(adapter);
    pipes[0] = reader;
    pipes[1] = writer;

    return Nothing();
  }
}

} // namespace os {

namespace std {

  template <>
  struct hash<os::WindowsFD>
  {
    using argument_type = os::WindowsFD;
    using result_type = size_t;

    result_type operator()(const argument_type& fd) const
    {
      switch (fd.type_()) {
      case os::WindowsFD::FD_FILE: {
        return static_cast<result_type>(fd.crt());
      }
      case os::WindowsFD::FD_HANDLE: {
        return reinterpret_cast<result_type>(static_cast<HANDLE>(fd));
      }
      case os::WindowsFD::FD_SOCKET: {
        return static_cast<result_type>(static_cast<SOCKET>(fd));
      }
      }
      UNREACHABLE();
    }
  };

} // namespace std {

#endif  // __STOUT_OS_WINDOWS_FILEDESCRIPTOR__
