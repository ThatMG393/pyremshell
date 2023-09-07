#!/usr/bin/python

# Python reverse shell client made by ThatMG393
# This is a client file, this connects to the server

import socket
import struct
import threading
import sys


class ThreadExt(threading.Thread):
    """Threading class that has a `stop()` function
    Your code should regularly check if the thread is running using `is_running`
    """

    def __init__(self, target, args: tuple = ()) -> None:
        super(ThreadExt, self).__init__(target=target, args=args)
        self.is_running = False
        self.daemon = True

    def start(self) -> None:
        """Starts the thread"""
        self.is_running = True
        super().start()

    def stop(self) -> None:
        """Stops the thread"""
        self.is_running = False


# Based on osid alary `senrev` class
# This is mostly it but formatted
class SockSendRecv:
    """Class to automatically handle sending and receiving bytes in packets"""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    def send(self, data: bytes) -> None:
        """
        Sends data to the socket

        :param data: bytes:

        """
        packet = struct.pack(">I", len(data)) + data
        self.sock.sendall(packet)

    def recv_packet(self) -> bytes:
        """Receive bytes as a packet"""
        packet_len = self.recv(4)
        if not packet_len:
            return b""

        packet_len = struct.unpack(">I", packet_len)[0]
        return self.recv(packet_len)

    def recv(self, n: int) -> bytes:
        """
        Receive `n` amount of bytes

        :param n: int:

        """
        packet = b""

        while (
            getattr(
                threading.current_thread(),
                "is_running",
                True) and len(packet) < n):
            frame = self.sock.recv(n - len(packet))
            if not frame:
                return b""

            packet += frame

        return packet

    def wait_for_packet(self, packet: bytes) -> bool:
        """
        Wait for specified packet to arrive

        :param packet: bytes:
        :returns bool:

        """
        while getattr(threading.current_thread(), "is_running", True):
            recv_packet = self.recv_packet()
            if recv_packet == packet:
                return True

        return False


class Logger:
    def __init__(self, tag: str) -> None:
        self.tag = tag

    def info(self, msg) -> None:
        print(f"{self.tag}", "[I]:", msg)

    def warn(self, msg) -> None:
        print(f"{self.tag}", "[W]:", msg)

    def err(self, msg) -> None:
        print(f"{self.tag}", "[E]:", msg)


class Client:
    """Client of the remote shell server"""

    def __init__(self) -> None:
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_senrev = SockSendRecv(self.client_socket)
        self.logger = Logger(
            ":".join(str(elem) for elem in self.client_socket.getsockname())
        )

        self.server_msg_recieving = False
        self.block_input = False
        self.server_cwd = "?"
        self.server_msg_thread = ThreadExt(self.server_msg_recv)

    def connect(self, ip: str, port: int) -> None:
        """
        Connects to the server

        :param ip: str:
        :param port: int:

        """
        try:
            self.client_socket.connect((ip, port))

            self.logger.info("Waiting for connected packet")
            welcome_packet = self.sock_senrev.recv_packet()

            if welcome_packet == "/req_auth".encode():
                self.logger.info("Server requires authuentication")
                token = input("Token: ").strip()
                self.sock_senrev.send(token.encode())
                
                if self.sock_senrev.recv_packet() == "/granted".encode():
                    self.logger.info("Success!")
                    welcome_packet = self.sock_senrev.recv_packet()
                else:
                    self.logger.err("Wrong token!")
                    exit(1)

            if welcome_packet == "/connected".encode():
                self.logger.info("Received connected packet")
                self.sock_senrev.send("/received_connected".encode())
                self.server_cwd = (
                    self.sock_senrev.recv_packet()
                    .decode("utf-8")
                    .replace("/cwd_changed", "", 1)
                    .strip()
                )

                self.start()
            else:
                self.logger.err("Server did not send a connected packet...")
                self.stop(1)
        except (ConnectionResetError, ConnectionRefusedError):
            self.logger.err(
                f"Can't connect to {ip}:{port} is the server is running?")
        except KeyboardInterrupt:
            self.logger.info("Catching interrupt and exiting")
            self.stop()

    def start(self) -> None:
        """Starts the shell and server message reciever"""
        self.server_msg_thread.start()
        self.shell()

    def stop(self, code: int = 0) -> None:
        """Stops the shell and server message reciever"""
        self.server_msg_thread.stop()
        self.sock_senrev.send("/exit".encode())
        exit(code)

    def shell(self) -> None:
        """A make-up shell used for sending commands to the server"""
        self.logger.info("Starting shell...")
        print()

        while self.server_msg_thread.is_running:
            if not self.block_input:
                command = input(f"{self.server_cwd} $ ").strip()
                if command:
                    if command == "/exit" or command == "exit":
                        self.sock_senrev.send("/exit".encode())
                        self.stop()
                    else:
                        self.sock_senrev.send(command.encode())
                        self.block_input = True

    def server_msg_recv(self) -> None:
        """Handles messages from the server"""
        self.logger.info("Starting server message reciever thread")

        while self.server_msg_thread.is_running:
            try:
                server_message = self.sock_senrev.recv_packet().decode("utf-8")
                if server_message:
                    if server_message == "/end_block_input":
                        self.block_input = False
                    elif "/cwd_changed" in server_message:
                        self.server_cwd = server_message.replace(
                            "/cwd_changed", "", 1
                        ).strip()
                    elif server_message == "/server_conn_shutdown":
                        self.logger.info("Server shutting down!")
                        self.stop()
                    else:
                        print(server_message)
            except OSError as e:
                if "Errno 9" in str(e):
                    self.logger.err(
                        "Connection to server has been unexpectedly closed..."
                    )
                    self.stop(1)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"{sys.argv[0]} requires 2 argument got {len(sys.argv) - 1}")
        print(f"{sys.argv[0]}: <ip> <port>")
    else:
        client = Client()
        client.connect(str(sys.argv[1]), int(sys.argv[2]))
