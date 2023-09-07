#!/usr/bin/python

# Python reverse shell server made by ThatMG393
# This is a server file, handles mostly
# the connections from client

import socket
import datetime
import struct
import os
import threading
import subprocess
import random
import string
import sys
from concurrent.futures import Future


# Global functions
def gen_token(size: int = 24) -> str:
    """
    Generates token with specified size
    :param size:  (Default value = 24)

    """
    generated = "".join(
        [
            random.choice(
                string.ascii_uppercase + string.ascii_lowercase + string.digits
            )
            for n in range(size)
        ]
    )
    return generated


# Annotations
def threaded(fn):
    """
    Marks a function threaded

    :param fn:

    """

    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
        thread.daemon = True
        thread.start()

    return wrapper


SERVER_REQUIRE_AUTH = True
SERVER_TOKEN = os.getenv("REMSHELL_TOKEN")
DEFAULT_CWD = os.getcwd()


class ThreadExt(threading.Thread):
    """Threading class that has a `stop()` function
    Your code should regularly check if the thread is running using `is_running()`
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


class Server:
    """Server of the remote shell"""

    def __init__(self, ip: str, port: int) -> None:
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((ip, port))
        except OSError as e:
            if "Errno 98" in str(e):
                print(f"An application is using the current port '{port}'")
                exit(1)

        self.server_clients = []

    def start(self) -> None:
        """Starts the server and listen for incoming clients"""
        self.server_socket.listen(1)
        print(
            f"Server running at { ':'.join(str(elem) for elem in self.server_socket.getsockname()) } on { datetime.datetime.now().strftime('%c') }"
        )

        try:
            while True:
                client, addr = self.server_socket.accept()
                print(f"A client connected from { addr[0] }:{ addr[1] }")

                self.new_client(client, addr)
        except KeyboardInterrupt:
            print("Catching interrupt and exiting")
            for client in self.server_clients:
                try:
                    client.stop()
                except Exception:
                    print("Caught an exception while shutting down, ingoring...")

            self.server_socket.shutdown(socket.SHUT_RDWR)
            self.server_socket.close()
            exit(0)

    def new_client(self, client: socket.socket, addr: tuple[str, int]) -> None:
        """
        Creates a new `ServerClient` then append it
        to the `self.server_clients` list

        :param client: socket.socket:
        :param addr: tuple[str, int]:

        """
        server_client = ServerClient(client, addr)
        self.server_clients.append(server_client)

        server_client.connect()


class ServerClient:
    """The client of the `Server`"""

    def __init__(
        self, client_socket: socket.socket, client_addr: tuple[str, int]
    ) -> None:
        self.logger = Logger(f"{client_addr[0]}:{client_addr[1]}")

        self.client_socket = client_socket
        self.sock_senrev = SockSendRecv(client_socket)
        self.current_wd = DEFAULT_CWD
        self.client_thread = ThreadExt(self.client_msg_handler)

    def auth(self) -> bool:
        """Authuenticate with the client"""
        self.sock_senrev.send("/req_auth".encode())
        token = self.sock_senrev.recv_packet().decode("utf-8")

        if token == SERVER_TOKEN:
            self.sock_senrev.send("/granted".encode())
            return True

        self.logger.err("Client failed authuenticating.")
        self.sock_senrev.send("/invalid".encode())
        return False

    @threaded
    def connect(self) -> None:
        """Connect to the client"""
        if SERVER_REQUIRE_AUTH:
            self.logger.info("Asking for authuentication")
            if self.auth():
                self.logger.info("Authuenticated!")
            else:
                self.client_socket.close()
                return

        self.logger.info("Sending connected packet")
        self.sock_senrev.send("/connected".encode())
        if self.sock_senrev.wait_for_packet("/received_connected".encode()):
            self.logger.info("Client received connected packet")
            self.is_connected = True

            self.logger.info("Sending current WD")
            self.sock_senrev.send(f"/cwd_changed {self.current_wd}".encode())

            self.start()
        else:
            self.logger.err("Client did not respond to connected packet...")

    def start(self) -> None:
        """Start the client message handler"""
        if not self.client_thread.is_running:
            self.client_thread.start()

    def stop(self) -> None:
        """Stops the client message handler then disconnects from the client"""
        if self.client_thread.is_running:
            self.client_thread.stop()
            self.sock_senrev.send("/server_conn_shutdown".encode())
            self.logger.info(
                f"Disconnecting to client {self.client_socket.getpeername()}"
            )

    def client_msg_handler(self) -> None:
        """Handles the Client messages"""
        self.logger.info("Starting server client listener thread")

        while self.client_thread.is_running:
            command_in = self.sock_senrev.recv_packet().decode("utf-8")

            if command_in:
                self.logger.info(f"Received command {command_in}")
                if command_in == "/help":
                    self.handle_help()
                elif command_in == "/exit":
                    self.logger.info("/exit command invoked!")
                    self.stop()
                elif "/cmd" in command_in:
                    arg = command_in.replace("/cmd", "", 1).strip()
                    if not arg:
                        self.logger.warn("No argument provided, return")
                        self.sock_senrev.send(
                            "/cmd requires 1 argument, received zero".encode()
                        )
                    else:
                        self.logger.info(f"Executing '{arg}'!")
                        arg = arg.split(" ")
                        self.handle_cmd(arg)
                elif "/cd" in command_in:
                    arg = command_in.replace("/cd", "", 1).strip()

                    if not arg:
                        self.logger.warn("No argument provided, returning")
                        self.sock_senrev.send(
                            "/cd requires 1 argument, received zero".encode()
                        )
                    else:
                        self.logger.info(f"Chdir'ing to '{arg}'!")
                        arg = arg.split(" ")

                        if len(arg) == 1:
                            self.handle_cd(arg[0])
                        else:
                            self.logger.warn(
                                f"{len(arg)} argument provided, returning")
                            self.sock_senrev.send(
                                f"/cd requires 1 argument, received {len(arg)}".encode())
                else:
                    self.logger.warn(f"{command_in} is not a command")
                    self.sock_senrev.send(
                        f"{command_in} is not a valid command!".encode()
                    )

                self.end_block_input()

    def handle_help(self) -> None:
        """Handles the help command"""
        self.logger.info("/help command invoked!")
        self.sock_senrev.send("wasup".encode())

    def handle_cmd(self, cmd: list[str]) -> None:
        """Handles the cmd command

        :param cmd: str[]:

        """
        self.logger.info("/cmd command invoked!")
        try:
            process = subprocess.Popen(
                cmd,
                # shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = process.communicate()

            self.sock_senrev.send(stdout.strip())
            if stderr.strip():
                self.sock_senrev.send(stderr.strip())
        except Exception as e:
            self.logger.err(f"Exception! {type(e)}: {e}")
            self.sock_senrev.send(
                f"Caught an exception before executing process: {e}".encode()
            )

    def handle_cd(self, folder: str) -> None:
        """
        Handles the cd command

        :param folder: str:

        """
        self.logger.info("/cd command invoked!")

        try:
            os.chdir(folder)
            self.current_wd = os.getcwd()
            self.logger.info(f"Chdir'ed to '{self.current_wd}'")
            self.sock_senrev.send(f"/cwd_changed {self.current_wd}".encode())
        except FileNotFoundError:
            self.sock_senrev.send(
                f"Directory {folder} doesn't exists!".encode())
        except NotADirectoryError:
            self.sock_senrev.send(f"{folder} is not a directory!".encode())
        except Exception as e:
            self.logger.err(f"Exception! {type(e)}: {e}")
            self.sock_senrev.send(
                f"Caught an exception before running `os.chdir()`: {e}".encode())

    def end_block_input(self) -> None:
        """Ends the client wait for result mode"""
        self.sock_senrev.send("/end_block_input".encode())


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"{sys.argv[0]} requires 2 argument got {len(sys.argv) - 1}")
        print(f"{sys.argv[0]}: <ip> <port>")
    else:
        if SERVER_REQUIRE_AUTH:
            if SERVER_TOKEN is None or not SERVER_TOKEN.strip():
                SERVER_TOKEN = gen_token()
                print("New token is generated each server restart.")
                print(
                    "You can set the manually token by setting 'REMSHELL_TOKEN' in the env"
                )

            print(f"This is the server token: {SERVER_TOKEN}")

        rem_serv = Server(str(sys.argv[1]), int(sys.argv[2]))
        rem_serv.start()
