#
# Copyright 2024 The University of Queensland
# Author: Alex Wilson <alex@uq.edu.au>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import sys
import json
import hmac
import uuid
import errno
import hashlib
import os
import datetime
import threading
from pprint import pformat
import logging
import argparse
import subprocess
from tornado.log import LogFormatter

import asyncio
import zmq
import aiozmq

DELIM = b"<IDS|MSG>"
engine_id = str(uuid.uuid4())

KERNEL_SCRIPT = """
import json
import os
fname = os.path.expanduser("{fname}")
from jupyter_client import write_connection_file
write_connection_file(fname=fname, ip="{ip}", key=b"{key}", transport="{transport}", signature_scheme="{signature_scheme}", kernel_name="{kernel_name}")
fd = open(fname, "r")
ci = json.loads(fd.read())
fd.close()
ports = json.dumps({{k:v for k,v in ci.items() if "_port" in k}})
print(ports)
"""

log_fmt = (
    "%(color)s[%(levelname)1.1s %(asctime)s.%(msecs).03d " "%(name)s]%(end_color)s %(message)s"
)
log_datefmt = "%H:%M:%S"
log = logging.getLogger('comp4703-ipykernel')
log_level = os.environ.get('LOG_LEVEL', default = 'INFO')
log.setLevel(log_level)
console = logging.StreamHandler(stream = sys.stderr)
console.setLevel(log_level)
console.setFormatter(LogFormatter(fmt=log_fmt, datefmt=log_datefmt))
log.addHandler(console)

rki = None
last_header = None
pid = None

cmd_waiting = None
cmd_reply = None
first_cmd_events = {
    'received': asyncio.Event(),
    'sent': asyncio.Event(),
    'completed': asyncio.Event()
}

# Utility functions:
async def shutdown():
    global loop, args
    if pid is not None:
        log.info('killing remote ipykernel (pid = %d)', pid)
        await execute('ssh', args.host, f"kill {pid}")
    log.info('going down')
    loop.stop()

def msg_id():
    """ Return a new uuid for message id """
    return str(uuid.uuid4())

def str_to_bytes(s):
    return s.encode('ascii')

def sign(msg_lst):
    h = auth.copy()
    for m in msg_lst:
        h.update(m)
    return str_to_bytes(h.hexdigest())

def new_header(msg_type):
    return {
            "date": datetime.datetime.now().isoformat(),
            "msg_id": msg_id(),
            "username": "kernel",
            "session": engine_id,
            "msg_type": msg_type,
            "version": "5.0",
        }

async def forward(stream, msg, identities):
    header = msg['header']

    def encode(msg):
        return str_to_bytes(json.dumps(msg))

    msg_lst = [
        encode(msg['header']),
        encode(msg['parent_header']),
        encode(msg['metadata']),
        encode(msg['content']),
    ]
    signature = sign(msg_lst)
    parts = [DELIM,
             signature,
             msg_lst[0],
             msg_lst[1],
             msg_lst[2],
             msg_lst[3]]
    if identities:
        parts = identities + parts
    stream.write(parts)
    await stream.drain()

async def send(stream, msg_type, content=None, parent_header=None, metadata=None, identities=None):
    header = new_header(msg_type)
    if content is None:
        content = {}
    if parent_header is None:
        parent_header = {}
    if metadata is None:
        metadata = {}

    def encode(msg):
        return str_to_bytes(json.dumps(msg))

    msg_lst = [
        encode(header),
        encode(parent_header),
        encode(metadata),
        encode(content),
    ]
    signature = sign(msg_lst)
    parts = [DELIM,
             signature,
             msg_lst[0],
             msg_lst[1],
             msg_lst[2],
             msg_lst[3]]
    if identities:
        parts = identities + parts
    stream.write(parts)
    await stream.drain()

kernel_info = {
    "status": "ok",
    "protocol_version": "5.3",
    "ipython_version": [1, 1, 0, ""],
    "language_version": [0, 0, 1],
    "language": "python",
    "implementation": "ipython",
    "implementation_version": "8.12.2",
    "language_info": {
        "name": "ipython",
        "version": "3.8",
        'mimetype': "",
        'file_extension': ".py",
        'pygments_lexer': "ipython3",
        'codemirror_mode': "",
        'nbconvert_exporter': "python",
    },
    "banner": "Python 3.8.17 (GPU remote via SSH)"
}

# Socket Handlers:
async def shell_handler(wire_msg):
    global streams, cmd_waiting, cmd_reply, rki, last_header
    global first_cmd_events
    #log.info('shell received: %s', json.dumps(msg))
    if 'remote_shell' in streams:
        shell = streams['shell']
        rshell = streams['remote_shell']
        rshell.write(wire_msg)
        await rshell.drain()
        rmsg = await rshell.read()
        shell.write(rmsg)
        await shell.drain()
        return

    identities, msg = deserialize_wire_msg(wire_msg)

    if msg['header']['msg_type'] == 'is_complete_request':
        content = {
            'status': 'unknown',
        }
        await send(streams['shell'], 'is_complete_reply', content,
            parent_header=msg['header'], identities=identities)
    elif msg['header']['msg_type'] == 'kernel_info_request':
        rki = wire_msg
        await send(streams['shell'], 'kernel_info_reply', kernel_info,
            parent_header = msg['header'], identities = identities)
        content = {
            'execution_state': 'idle',
        }
        await send(streams['iopub'], 'status', content,
            parent_header=msg['header'])
    elif msg['header']['msg_type'] == 'history_request':
        content = {
            'status': 'ok',
            'history': []
        }
        await send(streams['shell'], 'history_reply', content,
            parent_header = msg['header'], identities = identities)
    else:
        last_header = msg['header']

        content = {'execution_state': 'busy'}
        await send(streams['iopub'], 'status', content,
            parent_header = msg['header'])
        content = {'execution_count': 1, 'code': msg['content']['code']}
        await send(streams['iopub'], 'execute_input', content,
            parent_header = msg['header'])

        cmd_waiting = wire_msg
        first_cmd_events['received'].set()

        await first_cmd_events['completed'].wait()

        cmd_waiting = None
        streams['shell'].write(cmd_reply)
        await streams['shell'].drain()

def deserialize_wire_msg(wire_msg):
    """split the routing prefix and message frames from a message on the wire"""
    delim_idx = wire_msg.index(DELIM)
    identities = wire_msg[:delim_idx]
    m_signature = wire_msg[delim_idx + 1]
    msg_frames = wire_msg[delim_idx + 2:]

    def decode(msg):
        return json.loads(msg.decode('ascii'))

    m = {}
    m['header']        = decode(msg_frames[0])
    m['parent_header'] = decode(msg_frames[1])
    m['metadata']      = decode(msg_frames[2])
    m['content']       = decode(msg_frames[3])
    check_sig = sign(msg_frames)
    if check_sig != m_signature:
        raise ValueError(f"Signatures do not match: {check_sig} vs {m_signature}")

    return identities, m

async def control_handler(wire_msg):
    global exiting
    if 'remote_control' in streams:
        streams['remote_control'].write(wire_msg)
        await streams['remote_control'].drain()
        rmsg = await streams['remote_control'].read()
        streams['control'].write(rmsg)
        await streams['control'].drain()
    identities, msg = deserialize_wire_msg(wire_msg)
    log.debug("control received: %s", wire_msg)
    if msg['header']['msg_type'] == 'kernel_info_request':
        rki = wire_msg
        await send(streams['control'], 'kernel_info_reply', kernel_info,
            parent_header = msg['header'], identities = identities)
        content = {'execution_state': 'idle'}
        await send(streams['iopub'], 'status', content,
            parent_header=msg['header'])
    elif msg['header']["msg_type"] == "shutdown_request":
        await shutdown()

async def iopub_handler(wire_msg):
    identities, msg = deserialize_wire_msg(wire_msg)
    log.debug("iopub received: %s", json.dumps(wire_msg))

async def stdin_handler(wire_msg):
    if not 'remote_stdin' in streams:
        await first_command_events['sent'].wait()

    streams['remote_stdin'].write(wire_msg)
    await streams['remote_stdin'].drain()
    rmsg = await streams['remote_stdin'].read()
    streams['stdin'].write(rmsg)
    await streams['stdin'].drain()

parser = argparse.ArgumentParser(prog = 'comp4703-ipykernel')
parser.add_argument('-f', '--connection-file', type=str, help='Jupyter kernel connection file path')
parser.add_argument('-H', '--host', type=str, help='Remote host for SSH connection')
parser.add_argument('-r', '--rsync', type=str, action='append', help='Path to rsync to remote')
parser.add_argument('-P', '--python', type=str, help='Remote path to python interpreter')
parser.add_argument('-t', '--timeout', type=int, help='Timeout for ssh actions')
parser.add_argument('-e', '--env', type=str, action='append', help='Env var to set on remote side')

args = parser.parse_args()

if args.connection_file:
    log.info("Reading config file '%s'..." % args.connection_file)
    config = json.loads("".join(open(args.connection_file).readlines()))
else:
    log.info("Starting comp4703-kernel with default args...")
    config = {
        'control_port'      : 0,
        'hb_port'           : 0,
        'iopub_port'        : 0,
        'ip'                : '127.0.0.1',
        'key'               : str(uuid.uuid4()),
        'shell_port'        : 0,
        'signature_scheme'  : 'hmac-sha256',
        'stdin_port'        : 0,
        'transport'         : 'tcp'
    }

connection = config["transport"] + "://" + config["ip"]
secure_key = str_to_bytes(config["key"])
signature_schemes = {"hmac-sha256": hashlib.sha256}
auth = hmac.HMAC(
    secure_key,
    digestmod=signature_schemes[config["signature_scheme"]])
execution_count = 1
streams = {}

async def heartbeat_task():
    global config, connection
    socket = await aiozmq.create_zmq_stream(zmq.REP,
        bind = f"{connection}:{config['hb_port']}")
    streams['hb'] = socket
    while True:
        msg = await socket.read()
        if 'remote_hb' in streams:
            streams['remote_hb'].write(msg)
            await streams['remote_hb'].drain()
            rmsg = await streams['remote_hb'].read()
            socket.write(rmsg)
            await socket.drain()
        else:
            socket.write(msg)
            await socket.drain()

async def iopub_task():
    global config, connection
    socket = await aiozmq.create_zmq_stream(zmq.PUB,
        bind = f"{connection}:{config['iopub_port']}")
    streams['iopub'] = socket
    while True:
        msg = await socket.read()
        await iopub_handler(msg)

async def control_task():
    global config, connection
    socket = await aiozmq.create_zmq_stream(zmq.ROUTER,
        bind = f"{connection}:{config['control_port']}")
    streams['control'] = socket
    while True:
        data = await socket.read()
        await control_handler(data)

async def stdin_task():
    global config, connection
    socket = await aiozmq.create_zmq_stream(zmq.ROUTER,
        bind = f"{connection}:{config['stdin_port']}")
    streams['stdin'] = socket
    while True:
        data = await socket.read()
        await stdin_handler(data)

async def shell_task():
    global config, connection
    socket = await aiozmq.create_zmq_stream(zmq.ROUTER,
        bind = f"{connection}:{config['shell_port']}")
    streams['shell'] = socket
    while True:
        data = await socket.read()
        await shell_handler(data)

async def execute(prog, *argv):
    try:
        proc = await asyncio.create_subprocess_exec(prog, *argv,
            stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            return 0, stderr.decode('utf-8'), stdout.decode('utf-8')
        else:
            return proc.returncode, stderr.decode('utf-8'), stdout.decode('utf-8')
    except Exception as exc:
        return -1, str(exc), str(exc)

async def ssh_client_task():
    global args, cmd_waiting, cmd_reply, first_cmd_events, pid

    fname = None
    ports = None

    while True:
        while not 'iopub' in streams:
            await asyncio.sleep(1)

        await first_cmd_events['received'].wait()

        await send_stderr("> Connecting to GPU node...\n")

        try:
            rc, stderr, stdout = await asyncio.wait_for(
                execute('ssh', args.host, 'id'), timeout = 600)
            if not (rc == 0 and stdout.startswith('uid=')):
                await send_stderr(f"> Failed to connect to GPU node:\n{stdout}\n{stderr}\n")
                await asyncio.sleep(5)
                break
        except TimeoutError:
            await send_stderr(f"> Timed out. Will retry...\n")
            await asyncio.sleep(5)
            continue

        await send_stderr('> Connected OK\n')

        for d in args.rsync:
            from_dir = d
            to_dir = d
            parts = d.split(':')
            if len(parts) > 1:
                from_dir = parts[0]
                to_dir = parts[1]
            await send_stderr(f"> Synchronising {from_dir}...\n")
            rc, stderr, stdout = await execute('rsync', '-avh', '--inplace',
                '--partial', '--delete', '--size-only',
                from_dir, args.host + ':' + to_dir)
            if rc != 0:
                await send_stderr(f"WARNING: {from_dir} sync failed:\n{stderr}\n")

        pid = None
        if fname is not None:
            rc, stderr, stdout = await execute('ssh', args.host,
                f"cat {fname}")
            if rc != 0:
                log.info('failed to read old connection file, start a new ipykernel')
                fname = None
                ports = None
        if fname is not None:
            obj = json.loads(stdout)
            if obj['shell_port'] != ports['shell_port']:
                log.info('failed to read old connection file, start a new ipykernel')
                fname = None
                ports = None
        if fname is not None:
            rc, stderr, stdout = await execute('ssh', args.host,
                f"pgrep -af {fname}")
            if rc != 0:
                log.info('failed to find ipykernel process, start a new one')
                fname = None
                ports = None
            else:
                if not (args.python in stdout and \
                        '-m ipykernel_launcher' in stdout and\
                        fname in stdout):
                    log.info('failed to find ipykernel process, start a new one')
                    fname = None
                    ports = None
                else:
                    pid = int(stdout.split()[0])

        if fname is None:
            start_kernel = True

            myid = str(uuid.uuid4())
            fname = "/tmp/.ssh_ipykernel_%s.json" % myid  # POSIX path
            script = KERNEL_SCRIPT.format(fname = fname, **config)

            rc, stderr, stdout = await execute('ssh', args.host,
                f"{args.python} -c '{script}'")
            if rc != 0:
                await send_stderr(f"> Failed to run setup script on GPU node:\n{stderr}\n")
                await asyncio.sleep(10)
                continue

            ports = None
            try:
                ports = json.loads(stdout)
            except Exception as exc:
                await send_stderr(f"> Failed to parse output from setup script ({exc}):\n{stdout}\n")
                await asyncio.sleep(5)
                continue

        argv = ['-T']
        argv.append('-L')
        argv.append(f"{ports['shell_port']}:127.0.0.1:{ports['shell_port']}")
        argv.append('-L')
        argv.append(f"{ports['iopub_port']}:127.0.0.1:{ports['iopub_port']}")
        argv.append('-L')
        argv.append(f"{ports['stdin_port']}:127.0.0.1:{ports['stdin_port']}")
        argv.append('-L')
        argv.append(f"{ports['control_port']}:127.0.0.1:{ports['control_port']}")
        argv.append('-L')
        argv.append(f"{ports['hb_port']}:127.0.0.1:{ports['hb_port']}")
        argv.append(args.host)

        await send_stderr(f"> Starting remote ipykernel...\n")

        proc = await asyncio.create_subprocess_exec('ssh', *argv,
            stdin = subprocess.PIPE,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE)

        if pid is None:
            proc.stdin.write(
                f"nohup {args.python} -m ipykernel_launcher -f {fname}\n".encode('utf-8'))
        else:
            proc.stdin.write(f"wait {pid}\n".encode('utf-8'))
        await proc.stdin.drain()

        await proc.stdout.readline()

        rc, stderr, stdout = await execute('ssh', args.host, f"pgrep -af {fname}")
        if rc == 0:
            pid = int(stdout.split()[0])

        iopub = await aiozmq.create_zmq_stream(zmq.SUB,
            connect = f"tcp://127.0.0.1:{ports['iopub_port']}")
        iopub.transport.subscribe(b'')
        loop.create_task(remote_iopub_relay_task(iopub))

        hb = await aiozmq.create_zmq_stream(zmq.REQ,
            connect = f"tcp://127.0.0.1:{ports['hb_port']}")
        control = await aiozmq.create_zmq_stream(zmq.REQ,
            connect = f"tcp://127.0.0.1:{ports['control_port']}")
        shell = await aiozmq.create_zmq_stream(zmq.REQ,
            connect = f"tcp://127.0.0.1:{ports['shell_port']}")
        stdin = await aiozmq.create_zmq_stream(zmq.REQ,
            connect = f"tcp://127.0.0.1:{ports['stdin_port']}")

        streams['remote_control'] = control
        streams['remote_shell'] = shell
        streams['remote_stdin'] = stdin

        await one_heartbeat(hb)
        loop.create_task(remote_heartbeat(hb))

        if rki is not None:
            await send_stderr(f"> Getting remote kernel info...\n")

            shell.write(rki)
            await shell.drain()

            wire_msg = await shell.read()
            identities, msg = deserialize_wire_msg(wire_msg)
            if msg['content']['status'] != 'ok':
                await send_stderr(f"> Failed to start remote kernel (status = {msg['content']['status']})\n")
                await asyncio.sleep(5)
                continue

        await send_stderr(f"> Replaying command...\n")
        shell.write(cmd_waiting)
        await shell.drain()
        first_cmd_events['sent'].set()

        cmd_reply = await shell.read()
        first_cmd_events['completed'].set()

        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            await send_stderr(f"> Connection died unexpectedly:\n{stderr.decode('utf-8')}\n> Will try to reconnect...\n")


async def send_stderr(msg):
    log.info("stderr: %s", msg.strip())
    content = {'name': 'stderr', 'text': msg}
    await send(streams['iopub'], 'stream', content,
        parent_header = last_header)

async def remote_iopub_relay_task(iopub):
    global streams
    while True:
        wire_msg = await iopub.read()
        streams['iopub'].write(wire_msg)
        await streams['iopub'].drain()

async def one_heartbeat(hb):
    data = [str(uuid.uuid4()).encode('utf-8')]
    hb.write(data)
    await hb.drain()
    rep = await hb.read()
    if rep[0] != data[0]:
        raise(Error('HEARTBEAT FAILURE'))

async def remote_heartbeat(hb):
    while True:
        await asyncio.sleep(10)
        try:
            await one_heartbeat(hb)
        except:
            pass

log.debug("Config: %s", json.dumps(config))
log.debug("Starting loop...")

loop = asyncio.new_event_loop()
loop.create_task(heartbeat_task())
loop.create_task(iopub_task())
loop.create_task(control_task())
loop.create_task(stdin_task())
loop.create_task(shell_task())
loop.create_task(ssh_client_task())
loop.run_forever()
