# log4check
A small Minecraft server to help players detect vulnerability to the Log4Shell exploit 🐚

**Tested to work between Minecraft versions 1.12.2 and 1.18.1!**

## Usage
Run: `python3 log4check.py`

Players can then connect to the server using the hostname and port described in `config.json`!

## How it works
log4check runs two different servers: a Minecraft server using the `quarry` library and a TCP server that only returns HTTP responses.

When a player connects to the Minecraft server, the server sends them a `${jndi:...}` string that contains the URL of the internal TCP server. If the Minecraft client is vulnerable, it will send requests to the TCP server, which in turn will let the Minecraft server know to disconnect the client. The TCP server sends an HTTP response so curious players reading their `latest.log` file can find a message if they navigate to the server with a web browser.

No valid LDAP is ever sent to clients.

## Warning
This was written in spare time and comes with no guarantees. While this tool makes its best effort to determine if a player is vulnerable to Log4Shell, in the event that the player does not query LDAP within five seconds, they may receive a false negative reading.
