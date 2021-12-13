# log4check
A small Minecraft server to help players detect vulnerability to the Log4Shell exploit 🐚

**Tested to work between Minecraft versions 1.12.2 and 1.18.1!**

## Usage
Run: `python3 log4check.py`

Players can then connect to the server using the hostname and port described in `config.json`!

## Warning
This was written in spare time and comes with no guarantees. While this tool makes its best effort to determine if a player is vulnerable to Log4Shell, in the event that the player does not query LDAP within five seconds, they may receive a false negative reading.