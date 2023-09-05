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
from concurrent.futures import Future


# Global functions
def gen_token(size=24) -> str:
    generated = "".join(
        [
            random.choice(
                string.ascii_uppercase + string.ascii_lowercase + string.digits
            )
            for n in range(size)
        ]
    )
    return generated


def call_with_future(fn, future, args, kwargs) -> None:
    try:
        result = fn(*args, **kwargs)
        future.set_result(result)
    except Exception as exc:
        future.set_exception(exc)


# Annotations
def threaded(fn):
    def wrapper(*args, **kwargs) -> Future:
        future = Future()
        threading.Thread(
            target=call_with_future, args=(fn, future, args, kwargs)
        ).start()
        return future

    return wrapper


SERVER_REQUIRE_AUTH = True
if SERVER_REQUIRE_AUTH:
    SERVER_TOKEN = gen_token()
    print(f"This is the server token: {SERVER_TOKEN}")
    print("New token is generated each server restart.")
    print()


# Based on osid alary `senrev` class
# This is mostly it but formatted
class SockSendRecv:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    def send(self, data: bytes) -> None:
        packet = struct.pack(">I", len(data)) + data
        self.sock.sendall(packet)

    def recv_packet(self) -> bytes:
        packet_len = self.recv(4)
        if not packet_len:
            return b""

        packet_len = struct.unpack(">I", packet_len)[0]
        return self.recv(packet_len)

    def recv(self, n: int) -> bytes:
        packet = b""

        while len(packet) < n:
            frame = self.sock.recv(n - len(packet))
            if not frame:
                return b""

            packet += frame

        return packet

    def wait_for_packet(self, packet: bytes) -> bool:
        while True:
            recv_packet = self.recv_packet()
            if recv_packet == packet:
                return True


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
    def __init__(self, ip: str, port: int) -> None:
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((ip, port))
        except OSError as e:
            if "Errno 98" in str(e):
                print(f"An application is using the current port '{port}'")

        self.server_clients = []

    def start(self) -> None:
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
                client.stop()

            self.server_socket.shutdown(socket.SHUT_RDWR)
            self.server_socket.close()

    def new_client(self, client: socket.socket, addr) -> None:
        server_client = ServerClient(client, addr)
        self.server_clients.append(server_client)

        server_client.connect()


class ServerClient:
    def __init__(self, client_socket: socket.socket, client_addr) -> None:
        self.logger = Logger(f"{client_addr[0]}:{client_addr[1]}")

        self.client_socket = client_socket
        self.sock_senrev = SockSendRecv(client_socket)
        self.current_wd = os.getcwd()

        self.is_running = False
        self.is_connected = False

    @threaded
    def auth(self) -> bool:
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
        if not self.is_connected:
            if SERVER_REQUIRE_AUTH:
                self.logger.info("Asking for authuentication")
                if self.auth().result():
                    self.logger.info("Authuenticated!")
                else:
                    self.client_socket.close()
                    return

            self.logger.info("Sending connected packet")
            self.sock_senrev.send("/connected".encode())
            if self.sock_senrev.wait_for_packet(
                    "/received_connected".encode()):
                self.logger.info("Client received connected packet")
                
                self.logger.info("Sending current WD")
                self.sock_senrev.send(
                    f"/cwd_changed {self.current_wd}".encode())

                self.is_connected = True
                self.start()
            else:
                self.logger.err(
                    "Client did not respond to connected packet...")

    def start(self) -> None:
        if not self.is_running and self.is_connected:
            self.is_running = True
            self.main()

    def stop(self) -> None:
        if self.is_running and self.is_connected:
            self.is_running = False
            self.sock_senrev.send("/server_shutdown".encode())

    @threaded
    def main(self) -> None:
        self.logger.info("Starting server client listener thread")
        while self.is_running:
            command_in = self.sock_senrev.recv_packet().decode("utf-8")

            if command_in:
                self.logger.info(f"Received command {command_in}")
                if command_in == "/help":
                    self.logger.info("/help command invoked!")

                    self.sock_senrev.send("wasup".encode())
                elif command_in == "/exit":
                    self.logger.info("/exit command invoked!")
                    self.stop()
                elif "/cmd" in command_in:
                    self.logger.info("/cmd command invoked!")

                    arg = command_in.replace("/cmd", "", 1).strip()

                    if not arg:
                        self.logger.warn("No argument provided, return")
                        self.sock_senrev.send(
                            "/cmd requires 1 argument, received zero".encode()
                        )
                    else:
                        self.logger.info(f"Executing {arg}!")
                        arg = arg.split(" ")

                        try:
                            process = subprocess.Popen(
                                arg,
                                # shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            )
                            stdout, stderr = process.communicate()

                            self.sock_senrev.send(stdout)
                            if stderr.strip():
                                self.sock_senrev.send(stderr)
                        except Exception as e:
                            self.logger.err(f"Exception! {type(e)}: {e}")
                            self.sock_senrev.send(
                                f"Caught an exception before executing process: {e}".encode())
                elif "/cd" in command_in:
                    self.logger.info("/cd command invoked!")

                    arg = command_in.replace("/cd", "", 1).strip()

                    if not arg:
                        self.logger.warn("No argument provided, returning")
                        self.sock_senrev.send(
                            "/cd requires 1 argument, received zero".encode()
                        )
                    else:
                        self.logger.info(f"Chdir'ing to {arg}!")
                        arg = arg.split(" ")

                        if len(arg) == 1:
                            try:
                                os.chdir(arg[0])
                                self.current_wd = os.getcwd()
                                self.logger.info(
                                    f"Chdir'ed to {self.current_wd}")
                                self.sock_senrev.send(
                                    f"/cwd_changed {self.current_wd}".encode()
                                )
                            except FileNotFoundError:
                                self.sock_senrev.send(
                                    f"Directory {arg[0]} doesn't exists!".encode())
                            except NotADirectoryError:
                                self.sock_senrev.send(
                                    f"{arg[0]} is not a directory!".encode()
                                )
                            except Exception as e:
                                self.logger.err(f"Exception! {type(e)}: {e}")
                                self.sock_senrev.send(
                                    f"Caught an exception before running `os.chdir()`: {e}".encode())
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

    def end_block_input(self) -> None:
        self.sock_senrev.send("/end_block_input".encode())


def start_server(ip: str, port: int) -> None:
    my_server = Server(ip, port)
    my_server.start()


if __name__ == "__main__":
    start_server("localhost", 6969)
