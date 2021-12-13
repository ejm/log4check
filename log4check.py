#!/usr/bin/env python3
"""
log4check - Check for players affected by the Log4Shell exploit

Built atop Quarry's server_chat_room example
"""

import asyncio
import json
import logging
import os

logging.basicConfig(level=logging.INFO)

loop = asyncio.get_event_loop()
from twisted.internet import asyncioreactor
asyncioreactor.install(loop)
from twisted.internet import reactor
from quarry.net.server import ServerFactory, ServerProtocol
from quarry.types.uuid import UUID
from quarry.data.data_packs import data_packs, dimension_types

def create_request_handler(factory):
    async def handle_request(reader, writer):
        addr = writer.get_extra_info('peername')
        writer.write("HTTP/1.1 200\nContent-Type: text/html;\n\n".encode())
        writer.write(f"{factory.config['messages']['webserver']}\n".encode())
        await writer.drain()
        writer.close()
        for player in factory.players:
            if player.remote_addr.host == addr[0]:
                player.close(factory.config["messages"]["vulnerable_kick"])
    return handle_request

class Log4CheckProtocol(ServerProtocol):

    def _join_game_1_16(self):
        entity_id = 0
        max_players = 0
        hashed_seed = 42
        view_distance = 2
        simulation_distance = 2
        game_mode = 3
        prev_game_mode = 3
        is_hardcore = False
        is_respawn_screen = True
        is_reduced_debug = False
        is_debug = False
        is_flat = False
        dimension_count = 1
        dimension_name = "check"
        dimension_type = dimension_types[self.protocol_version, "minecraft:the_end"]
        data_pack = data_packs[self.protocol_version]

        join_game = [
            self.buff_type.pack("i?BB", entity_id, is_hardcore, game_mode, prev_game_mode),
            self.buff_type.pack_varint(dimension_count),
            self.buff_type.pack_string(dimension_name),
            self.buff_type.pack_nbt(data_pack),
            self.buff_type.pack_nbt(dimension_type),
            self.buff_type.pack_string(dimension_name),
            self.buff_type.pack("q", hashed_seed),
            self.buff_type.pack_varint(max_players),
            self.buff_type.pack_varint(view_distance),
        ]

        if self.protocol_version >= 757:  # 1.18
            join_game.append(self.buff_type.pack_varint(simulation_distance))

        self.send_packet(
            "join_game",
            *join_game,
            self.buff_type.pack("????", is_reduced_debug, is_respawn_screen, is_debug, is_flat))

    def _join_game_1_15(self):
        # Send "Join Game" packet
        self.send_packet("join_game",
            self.buff_type.pack("iBiqB",
                0,                              # entity id
                3,                              # game mode
                1,                              # dimension
                0,                              # hashed seed
                0),                             # max players
            self.buff_type.pack_string("flat"), # level type
            self.buff_type.pack_varint(1),      # view distance
            self.buff_type.pack("??",
                False,                          # reduced debug info
                True))                          # show respawn screen

    def _join_game_1_14(self):
        self.send_packet("join_game",
            self.buff_type.pack("iBiB",
                0,                              # entity id
                3,                              # game mode
                0,                              # dimension
                0),                             # max players
            self.buff_type.pack_string("flat"), # level type
            self.buff_type.pack_varint(1),      # view distance
            self.buff_type.pack("?", False))    # reduced debug info

    def _join_game_1_12(self):
        self.send_packet("join_game",
            self.buff_type.pack("iBiBB",
                0,                              # entity id
                3,                              # game mode
                1,                              # dimension
                0,                              # max players
                0),                             # unused
            self.buff_type.pack_string("flat"), # level type
            self.buff_type.pack("?", False))    # reduced debug info

    def player_joined(self):
        # Call super. This switches us to "play" mode, marks the player as
        #   in-game, and does some logging.
        ServerProtocol.player_joined(self)

        # Send "Join Game" packet
        if self.protocol_version >= 736:
            self._join_game_1_16()
        elif self.protocol_version >= 573:
            self._join_game_1_15()
        elif self.protocol_version >= 477:
            self._join_game_1_14()
        else:
            self._join_game_1_12()

        # Send "Player Position and Look" packet
        if self.protocol_version >= 755:
            self.send_packet(
                "player_position_and_look",
                self.buff_type.pack("dddff?",
                    0,                         # x
                    255,                       # y
                    0,                         # z
                    0,                         # yaw
                    0,                         # pitch
                    0b00000),                  # flags
                self.buff_type.pack_varint(0), # teleport id
                self.buff_type.pack("?", True)) # Leave vehicle,
        else:
            self.send_packet("player_position_and_look",
                self.buff_type.pack("dddff?",
                    0,                         # x
                    255,                       # y
                    0,                         # z
                    0,                         # yaw
                    0,                         # pitch
                    0b00000),                  # flags
                self.buff_type.pack_varint(0)) # teleport id

        # Start sending "Keep Alive" packets
        self.ticker.add_loop(20, self.update_keep_alive)
        
        message = {"obfuscated": False, "text": "", "extra": [
            {"color": "black", "obfuscated": True, "text": "${jndi:ldap://" + self.factory.url + "}"},
            "\n",
            self.factory.config["messages"]["explanation"]
        ]}
        send_message(self, message)
        self.ticker.add_delay(100, self.safe_kick_player)

    def update_keep_alive(self):
        payload = self.buff_type.pack('Q', 0)
        self.send_packet("keep_alive", payload)

    def safe_kick_player(self):
        self.close(self.factory.config["messages"]["safe_kick"])

def send_message(client, message, sender=None):
    if sender is None:
        sender = UUID(int=0)
    data = client.buff_type.pack_json(message)

    # 1.8.x+
    if client.protocol_version >= 47:
        data += client.buff_type.pack('B', 0)

    # 1.16.x+
    if client.protocol_version >= 736:
        data += client.buff_type.pack_uuid(sender)

    client.send_packet("chat_message", data)

class Log4CheckFactory(ServerFactory):
    protocol = Log4CheckProtocol

async def start(handler, config):
    server = await asyncio.start_server(
        handler, config["webserver"]["host"], config["webserver"]["port"])
    async with server:
        await server.serve_forever()

def main():
    config_path = os.environ.get("LOG4CHECK_CONFIG", "config.json")
    with open(config_path) as f:
        config = json.load(f)

    # Create factory
    factory = Log4CheckFactory()
    factory.config = config
    factory.url = f"{config['webserver']['url']}:{config['webserver']['port']}"
    favicon = config["minecraft"].get("favicon", None)
    if favicon:
        factory.icon_path = favicon
    factory.motd = config["minecraft"]["motd"]

    handler = create_request_handler(factory)
    
    loop.create_task(start(handler, config))

    # Listen
    factory.listen(config["minecraft"]["host"], config["minecraft"]["port"])
    reactor.run()


if __name__ == "__main__":
    main()
