# Botoban
**:notes: Ban, ban, ban - with my Botoban ! :musical_note:**

## What is it ?

It's a script for banning IPs from your servers.

It uses journalctl, netfilter (iptables interface) and Lua.

## What do you need ?

1. Linux with systemd (obviously most of distros around).
1. Lua (scripting language available on every distro).

## Rights

You'll have to launch Botoban as root user, as it uses iptables.


## Features
1. Does not lie in memory, exit when the job is done.
1. Use well known shell interfaces, doesn't reinvent wheel.
1. Use Lua table as its own database: no need to mess with external database.
1. Ban entire network, above a defined threshold of hosts IPs.

## Configuration


## Launch

## Credits

For serializing tables : tprint.lua from TsT (https://github.com/tst2005/lua-tprint/)
