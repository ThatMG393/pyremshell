#!/usr/bin/python

# Python reverse shell client made by ThatMG393
# This is a client file, this connects to the server

import socket
import datetime
import struct
import os
import time
import threading


# Annotations
def threaded(fn):
    def wrapper(*args, **kwargs) -> threading.Thread:
        thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
        thread.start()
        return thread
        
    return wrapper


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


class Client:
    def __init__(self) -> None:
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_senrev = SockSendRecv(self.client_socket)
        self.logger = Logger(
            ":".join(str(elem) for elem in self.client_socket.getsockname())
        )

        self.server_msg_running = False
        self.block_input = False
        self.server_cwd = "?"

    def connect(self, ip: str, port: int) -> None:
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
                self.start()
            else:
                self.logger.err("Server did not send a connected packet...")
                exit(1)
        except (ConnectionResetError, ConnectionRefusedError):
            self.logger.err(f"Can't connect to {ip}:{port} is the server is running?")
        except KeyboardInterrupt:
            self.logger.info("Catching interrupt and exiting")
            self.stop()

    def start(self) -> None:
        self.server_msg_running = True
        self.server_msg()
        self.main()

    def stop(self) -> None:
        self.server_msg_running = False

    def main(self) -> None:
        self.logger.info("Starting shell...")
        print()

        while self.server_msg_running:
            if not self.block_input:
                command = input(f"[{self.server_cwd}]: ").strip()
                if command:
                    if command == "/exit":
                        self.sock_senrev.send(command.encode())
                        self.stop()
                    else:
                        self.sock_senrev.send(command.encode())
                        self.block_input = True

    @threaded
    def server_msg(self) -> None:
        self.logger.info("Starting server message handler thread")
        while self.server_msg_running:
            server_message = self.sock_senrev.recv_packet().decode("utf-8")
            if server_message:
                if server_message == "/end_block_input":
                    self.block_input = False
                elif "/cwd_changed" in server_message:
                    self.server_cwd = server_message.replace(
                        "/cwd_changed", "", 1
                    ).strip()
                elif server_message == "/server_shutdown":
                    print("Server shutting down!")
                    self.stop()
                else:
                    print(server_message)


if __name__ == "__main__":
    client = Client()
    client.connect("localhost", 6969)
