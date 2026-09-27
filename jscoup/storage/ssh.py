# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Loopback-only SSH forwarding with strict OpenSSH known-host verification."""
import select,socketserver,threading

class SSHTunnel:
    def __init__(self,*,ssh_host,remote_bind_host,remote_bind_port,ssh_port=22,
                 ssh_username=None,ssh_password=None,ssh_pkey=None,local_bind_port=None,
                 known_hosts=None,connect_timeout=10):
        try:import paramiko
        except ImportError as exc:raise ImportError('Install jscoup[ssh] for SSH forwarding') from exc
        if not remote_bind_host or not 0<int(remote_bind_port)<65536:
            raise ValueError('A valid remote database host and port are required')
        self._client=paramiko.SSHClient()
        self._client.load_system_host_keys()
        if known_hosts:self._client.load_host_keys(known_hosts)
        self._client.set_missing_host_key_policy(paramiko.RejectPolicy())
        self._connect=dict(hostname=ssh_host,port=ssh_port,username=ssh_username,password=ssh_password,
                           key_filename=ssh_pkey,timeout=connect_timeout,banner_timeout=connect_timeout,auth_timeout=connect_timeout)
        self._remote=(remote_bind_host,int(remote_bind_port));self._port=local_bind_port or 0
        self._server=None;self._thread=None;self._started=False
    def start(self):
        if self._started:return self.local_bind_port
        try:
            self._client.connect(**self._connect)
            transport=self._client.get_transport();remote=self._remote
            class Handler(socketserver.BaseRequestHandler):
                def handle(handler):
                    channel=None
                    try:
                        channel=transport.open_channel('direct-tcpip',remote,handler.client_address,timeout=10)
                        if channel is None:return
                        while True:
                            readable,_,_=select.select([handler.request,channel],[],[],1)
                            if not transport.is_active():break
                            for src in readable:
                                data=src.recv(65536)
                                if not data:return
                                (channel if src is handler.request else handler.request).sendall(data)
                    except (OSError,EOFError):pass
                    finally:
                        if channel is not None:channel.close()
            class Server(socketserver.ThreadingTCPServer):
                allow_reuse_address=True
                daemon_threads=True
                # Bound active forwarding handlers to avoid thread growth.
                slots=threading.BoundedSemaphore(64)
                def process_request(server,request,address):
                    if not server.slots.acquire(False):server.shutdown_request(request);return
                    try:super().process_request(request,address)
                    except BaseException:server.slots.release();raise
                def process_request_thread(server,request,address):
                    try:super().process_request_thread(request,address)
                    finally:server.slots.release()
            self._server=Server(('127.0.0.1',self._port),Handler)
            self._thread=threading.Thread(target=self._server.serve_forever,daemon=True,name='jscoup-ssh')
            self._thread.start();self._started=True
            return self.local_bind_port
        except BaseException:
            self.stop();raise
    def stop(self):
        self._client.close()
        if self._server:
            if self._thread and self._thread.is_alive():self._server.shutdown()
            self._server.server_close();self._server=None
        self._started=False
    @property
    def local_bind_port(self):return self._server.server_address[1] if self._server else None
