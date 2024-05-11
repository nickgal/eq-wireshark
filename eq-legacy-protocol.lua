eq_protocol = Proto("everquest",  "EQ Legacy Protocol")

Flags = {
  UnknownBit0 = 0x0001,
  HasAckRequest = 0x0002,
  IsClosing = 0x0004,
  IsFragment = 0x0008,
  HasAckCounter = 0x0010,
  IsFirstPacket = 0x0020,
  IsClosing2 = 0x0040,
  IsSequenceEnd = 0x0080,
  IsKeepAliveAck = 0x0100,
  UnknownBit9 = 0x0200,
  HasAckResponse = 0x0400,
  UnknownBit11 = 0x0800,
  UnknownBit12 = 0x1000,
  UnknownBit13 = 0x2000,
  UnknownBit14 = 0x4000,
  UnknownBit15 = 0x8000
}

flags = ProtoField.new("Flags", "everquest.flags", ftypes.UINT16, nil, base.HEX)

flag_unknown_bit_0 = ProtoField.bool("everquest.flags.unknown_bit_0", "UnknownBit0", 16, nil, Flags.UnknownBit0)
flag_has_ack_request = ProtoField.bool("everquest.flags.has_ack_request", "HasAckRequest", 16, nil, Flags.HasAckRequest)
flag_is_closing = ProtoField.bool("everquest.flags.is_closing", "IsClosing", 16, nil, Flags.IsClosing)
flag_is_fragment = ProtoField.bool("everquest.flags.is_fragment", "IsFragment", 16, nil, Flags.IsFragment)
flag_has_ack_counter = ProtoField.bool("everquest.flags.has_ack_counter", "HasAckCounter", 16, nil, Flags.HasAckCounter)
flag_is_first_packet = ProtoField.bool("everquest.flags.is_first_packet", "IsFirstPacket", 16, nil, Flags.IsFirstPacket)
flag_is_closing_2 = ProtoField.bool("everquest.flags.is_closing_2", "IsClosing2", 16, nil, Flags.IsClosing2)
flag_is_sequence_end = ProtoField.bool("everquest.flags.is_sequence_end", "IsSequenceEnd", 16, nil, Flags.IsSequenceEnd)
flag_is_keep_alive_ack = ProtoField.bool("everquest.flags.is_keep_alive_ack", "IsKeepAliveAck", 16, nil, Flags.IsKeepAliveAck)
flag_unknown_bit_9 = ProtoField.bool("everquest.flags.unknown_bit_9", "UnknownBit9", 16, nil, Flags.UnknownBit9)
flag_has_ack_response = ProtoField.bool("everquest.flags.has_ack_response", "HasAckResponse", 16, nil, Flags.HasAckResponse)
flag_unknown_bit_11 = ProtoField.bool("everquest.flags.unknown_bit_11", "UnknownBit11", 16, nil, Flags.UnknownBit11)
flag_unknown_bit_12 = ProtoField.bool("everquest.flags.unknown_bit_12", "UnknownBit12", 16, nil, Flags.UnknownBit12)
flag_unknown_bit_13 = ProtoField.bool("everquest.flags.unknown_bit_13", "UnknownBit13", 16, nil, Flags.UnknownBit13)
flag_unknown_bit_14 = ProtoField.bool("everquest.flags.unknown_bit_14", "UnknownBit14", 16, nil, Flags.UnknownBit14)
flag_unknown_bit_15 = ProtoField.bool("everquest.flags.unknown_bit_15", "UnknownBit15", 16, nil, Flags.UnknownBit15)

header_sequence_number = ProtoField.uint16("everquest.header.sequence_number", "SequenceNumber", base.HEX)
header_ack_response = ProtoField.uint16("everquest.header.ack_response", "AckResponse", base.HEX)
header_ack_request = ProtoField.uint16("everquest.header.ack_request", "AckRequest", base.HEX)
header_fragment_sequence = ProtoField.uint16("everquest.header.fragment_sequence", "FragmentSequence", base.HEX)
header_fragment_current = ProtoField.uint16("everquest.header.fragment_current", "FragmentCurrent", base.HEX)
header_fragment_total = ProtoField.uint16("everquest.header.fragment_total", "FragmentTotal", base.HEX)
header_ack_counter_high = ProtoField.uint8("everquest.header.ack_counter_high", "AckCounterHigh", base.HEX)
header_ack_counter_low = ProtoField.uint8("everquest.header.ack_counter_low", "AckCounterLow", base.HEX)

opcode =  ProtoField.uint16("everquest.opcode", "OpCode", base.HEX)
payload =  ProtoField.bytes("everquest.payload", "Payload")
crc = ProtoField.uint32("everquest.crc", "CRC32", base.HEX)

motd_message =  ProtoField.string("everquest.motd.message", "Message")
login_accountname = ProtoField.string("everquest.login.accountname", "Account Name")
login_password = ProtoField.string("everquest.login.password", "Password")
login_unknown189 = ProtoField.bytes("everquest.login.unknown189", "Unknown")
login_zoning = ProtoField.bool("everquest.login.zoning", "Zoning")
login_unknown193 = ProtoField.bytes("everquest.login.unknown193", "Unknown")

rpserver_fv = ProtoField.bool("everquest.rpserver.fv", "FV rules")
rpserver_pvp = ProtoField.bool("everquest.rpserver.pvp", "PVP")
rpserver_auto_identify = ProtoField.bool("everquest.rpserver.auto_identify", "Auto Identify")
rpserver_namegen = ProtoField.bool("everquest.rpserver.namegen", "Name Gen")
rpserver_gibberish = ProtoField.bool("everquest.rpserver.gibberish", "Gibberish")
rpserver_testserver = ProtoField.bool("everquest.rpserver.testserver", "Test Server")
rpserver_locale = ProtoField.uint32("everquest.rpserver.locale", "Locale")
rpserver_profanity_filter = ProtoField.bool("everquest.rpserver.profanity_filter", "Profanity Filter")
rpserver_worldshortname = ProtoField.string("everquest.rpserver.worldshortname", "World Shortname")
rpserver_loggingserverpassword = ProtoField.string("everquest.rpserver.loggingserver_password", "Logging Server Password")
rpserver_loggingserveraddress = ProtoField.string("everquest.rpserver.loggingserver_address", "Logging Server Address")
rpserver_loggingserverport = ProtoField.uint32("everquest.rpserver.loggingserver_port", "Logging Server Port")
rpserver_localizedemailaddress = ProtoField.string("everquest.rpserver.localized_email", "Localized Email Address")
rpserver_unknown1 = ProtoField.bytes("everquest.rpserver.unknown1", "Unknown")
rpserver_unknown2 = ProtoField.bytes("everquest.rpserver.unknown2", "Unknown")

accessgranted_response = ProtoField.bool("everquest.access_granted.response", "Response")
accessgranted_name = ProtoField.string("everquest.access_granted.name", "Name")

eq_protocol.fields = {
  flags, flag_unknown_bit_0, flag_has_ack_request, flag_is_closing, flag_is_fragment, flag_has_ack_counter,
  flag_is_first_packet, flag_is_closing_2, flag_is_sequence_end, flag_is_keep_alive_ack, flag_unknown_bit_9,
  flag_has_ack_response, flag_unknown_bit_11, flag_unknown_bit_12, flag_unknown_bit_13, flag_unknown_bit_14, flag_unknown_bit_15,
  header_sequence_number, header_ack_response, header_ack_request, header_fragment_sequence, header_fragment_current,
  header_fragment_total, header_ack_counter_high, header_ack_counter_low, opcode, payload, crc,
  motd_message, login_accountname, login_password, login_unknown189, login_zoning, login_unknown193,
  rpserver_fv, rpserver_pvp, rpserver_auto_identify, rpserver_namegen, rpserver_gibberish, rpserver_testserver,
  rpserver_locale, rpserver_profanity_filter, rpserver_worldshortname, rpserver_loggingserverpassword,
  rpserver_loggingserveraddress, rpserver_loggingserverport, rpserver_localizedemailaddress, rpserver_unknown1,
  rpserver_unknown2, accessgranted_response, accessgranted_name,
}

function eq_protocol.dissector(buffer, pinfo, tree)
  local length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = eq_protocol.name

  local subtree = tree:add(eq_protocol, buffer(), "EQ Protocol Data")

  local crc_length = 4

  local flags_length = 2
  local flags_buffer = buffer(0,flags_length)
  local flags_value = flags_buffer:le_uint()
  local flag_tree = subtree:add(flags, flags_buffer)

  flag_tree:add_le(flag_unknown_bit_0, flags_buffer)
  flag_tree:add_le(flag_has_ack_request, flags_buffer)
  flag_tree:add_le(flag_is_closing, flags_buffer)
  flag_tree:add_le(flag_is_fragment, flags_buffer)
  flag_tree:add_le(flag_has_ack_counter, flags_buffer)
  flag_tree:add_le(flag_is_first_packet, flags_buffer)
  flag_tree:add_le(flag_is_closing_2, flags_buffer)
  flag_tree:add_le(flag_is_sequence_end, flags_buffer)
  flag_tree:add_le(flag_is_keep_alive_ack, flags_buffer)
  flag_tree:add_le(flag_unknown_bit_9, flags_buffer)
  flag_tree:add_le(flag_has_ack_response, flags_buffer)
  flag_tree:add_le(flag_unknown_bit_11, flags_buffer)
  flag_tree:add_le(flag_unknown_bit_12, flags_buffer)
  flag_tree:add_le(flag_unknown_bit_13, flags_buffer)
  flag_tree:add_le(flag_unknown_bit_14, flags_buffer)
  flag_tree:add_le(flag_unknown_bit_15, flags_buffer)

  local unknown_bit_0 = bit.band(flags_value, Flags.UnknownBit0) ~= 0
  local has_ack_request = bit.band(flags_value, Flags.HasAckRequest) ~= 0
  local is_closing = bit.band(flags_value, Flags.IsClosing) ~= 0
  local is_fragment = bit.band(flags_value, Flags.IsFragment) ~= 0
  local has_ack_counter = bit.band(flags_value, Flags.HasAckCounter) ~= 0
  local is_first_packet = bit.band(flags_value, Flags.IsFirstPacket) ~= 0
  local is_closing_2 = bit.band(flags_value, Flags.IsClosing2) ~= 0
  local is_sequence_end = bit.band(flags_value, Flags.IsSequenceEnd) ~= 0
  local is_keep_alive_ack = bit.band(flags_value, Flags.IsKeepAliveAck) ~= 0
  local unknown_bit_9 = bit.band(flags_value, Flags.UnknownBit9) ~= 0
  local has_ack_response = bit.band(flags_value, Flags.HasAckResponse) ~= 0
  local unknown_bit_11 = bit.band(flags_value, Flags.UnknownBit11) ~= 0
  local unknown_bit_12 = bit.band(flags_value, Flags.UnknownBit12) ~= 0
  local unknown_bit_13 = bit.band(flags_value, Flags.UnknownBit13) ~= 0
  local unknown_bit_14 = bit.band(flags_value, Flags.UnknownBit14) ~= 0
  local unknown_bit_15 = bit.band(flags_value, Flags.UnknownBit15) ~= 0

  local has_opcode = true

  local header_offset = flags_length

  local header_tree = subtree:add(eq_protocol, buffer(header_offset), "[Header]")

  header_tree:add(header_sequence_number, buffer(header_offset, 2))
  header_offset = header_offset + 2

  if has_ack_response then
    header_tree:add(header_ack_response, buffer(header_offset, 2))
    header_offset = header_offset + 2
  end

  if has_ack_request then
    header_tree:add(header_ack_request, buffer(header_offset, 2))
    header_offset = header_offset + 2
  end


  if is_fragment then
    header_tree:add(header_fragment_sequence, buffer(header_offset, 2))
    header_offset = header_offset + 2;

    header_tree:add(header_fragment_current, buffer(header_offset, 2))
    -- only the first fragment has an opcode
    has_opcode = buffer(header_offset, 2):int() == 0
    header_offset = header_offset + 2;

    header_tree:add(header_fragment_total, buffer(header_offset, 2))
    header_offset = header_offset + 2;
  end

  if has_ack_counter then
    header_tree:add(header_ack_counter_high, buffer(header_offset, 1))
    header_offset = header_offset + 1;
  end

  if has_ack_counter and has_ack_request then
    header_tree:add(header_ack_counter_low, buffer(header_offset, 1))
    header_offset = header_offset + 1;
  end

  header_tree:set_len(header_offset - flags_length)

  local bytes_remaining = length - header_offset - crc_length
  local opcode_data = nil
  if bytes_remaining > 0 and has_opcode then
    opcode_value = buffer(header_offset, 2):uint()
    opcode_data = OPCODE_TABLE[opcode_value]

    if opcode_data then
      pinfo.cols.info = "[" .. opcode_data.name .. "] " .. tostring(pinfo.cols['info'])
    end

    subtree:add(opcode, buffer(header_offset, 2), opcode_value, nil, opcode_data.name)
    header_offset = header_offset + 2
    bytes_remaining = bytes_remaining - 2
  end

  if bytes_remaining > 0 then
    add_payload(subtree, buffer(header_offset, bytes_remaining), opcode_data)
  end

  subtree:add_le(crc, buffer(length - crc_length, crc_length))
end

function add_payload(subtree, buffer, opcode_data)
  if opcode_data == nil or opcode_data.dissect == nil then
    subtree:add(payload, buffer)
  else
    local payload_subtree = subtree:add(eq_protocol, buffer, opcode_data.name)
    opcode_data.dissect(payload_subtree, buffer)
  end
end

local function add_string(tree, field, buffer)
  local s = buffer:string()
  local len = #s
  tree:add(field, buffer(0, len), s)

  -- Returns the length in case the next string is offset by it
  return len
end
local function add_uint_le(tree, field, buffer)
  -- For little endian uints (seems like this is the "standard")
  tree:add(field, buffer, buffer:le_uint())
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(5998, eq_protocol)
udp_port:add(9000, eq_protocol)

OPCODE_TABLE = {
  -- Opcodes with dissect handlers
  [0x0710] = {
    name ="MSG_ACCESS_GRANTED",
    dissect = function(tree, buffer)
      tree:add(accessgranted_response, buffer(0, 1))
      add_string(tree, accessgranted_name, buffer(1, 64))
    end
  },
  [0x5818] = {
    name ="MSG_LOGIN",
    dissect = function(tree, buffer)
      local password_offset = 1 + add_string(tree, login_accountname, buffer(0, 127))
      add_string(tree, login_password, buffer(password_offset, 15))

      tree:add(login_unknown189, buffer(151, 41))
      tree:add(login_zoning, buffer(192, 1))
      tree:add(login_unknown193, buffer(193, 3))
    end
  },
  [0xc341] = {
    name ="MSG_RPSERVER",
    dissect = function(tree, buffer)
      tree:add(rpserver_fv, buffer(0, 4))
      tree:add(rpserver_pvp, buffer(4, 4))
      tree:add(rpserver_auto_identify, buffer(8, 4))
      tree:add(rpserver_namegen, buffer(12, 4))
      tree:add(rpserver_gibberish, buffer(16, 4))
      tree:add(rpserver_testserver, buffer(20, 4))
      add_uint_le(tree, rpserver_locale, buffer(24, 4))
      tree:add(rpserver_profanity_filter, buffer(28, 4))
      add_string(tree, rpserver_worldshortname, buffer(32, 32))
      add_string(tree, rpserver_loggingserverpassword, buffer(64, 32))
      tree:add(rpserver_unknown1, buffer(96, 16))
      add_string(tree, rpserver_loggingserveraddress, buffer(112, 16))
      tree:add(rpserver_unknown2, buffer(126, 48))
      add_uint_le(tree, rpserver_loggingserverport, buffer(176, 4))
      add_string(tree, rpserver_localizedemailaddress, buffer(180, 64))
    end
  },
  [0xdd41] = {
    name ="MSG_MOTD",
    dissect = function(subtree, buffer)
      subtree:add(motd_message, buffer)
    end
  },

  -- Opcodes without handlers
  [0xbf41] = {
    name ="MSG_ABILITY_CHANGE",
  },
  [0x2470] = {
    name ="MSG_ACCOUNT_INUSE",
  },
  [0x2c40] = {
    name ="MSG_ADD_ILIST",
  },
  [0xed40] = {
    name ="MSG_ADD_LINK",
  },
  [0x0740] = {
    name ="MSG_ADD_MLIST",
  },
  [0x4170] = {
    name ="MSG_ADD_NAME",
  },
  [0x0520] = {
    name ="MSG_ADD_NPC",
  },
  [0xf640] = {
    name ="MSG_ADD_OBJECT",
  },
  [0x9940] = {
    name ="MSG_ADD_SHORTCUT",
  },
  [0xd241] = {
    name ="MSG_ADD_SOULMARK",
  },
  [0x9540] = {
    name ="MSG_ADD_SWITCH",
  },
  [0x0c20] = {
    name ="MSG_ADD_ZCMD",
  },
  [0x0541] = {
    name ="MSG_ALCHEMY",
  },
  [0x0b10] = {
    name ="MSG_ALIVE",
  },
  [0x4c41] = {
    name ="MSG_ALLOW_SCREENSHOTS",
  },
  [0x1442] = {
    name ="MSG_ALTERNATEADV",
  },
  [0xba41] = {
    name ="MSG_APPLY_POISON",
  },
  [0x3f42] = {
    name ="MSG_ARMY",
  },
  [0x4042] = {
    name ="MSG_ARMY_STRUCTURE",
  },
  [0x0042] = {
    name ="MSG_ASSIST_PLAYER",
  },
  [0x1a40] = {
    name ="MSG_AUCTION",
  },
  [0x4241] = {
    name ="MSG_AUTOSAVE_PC",
  },
  [0x5042] = {
    name ="MSG_AVATAR_BAZAAR",
  },
  [0xfa41] = {
    name ="MSG_AVATAR_CREATE_UTIL",
  },
  [0xf141] = {
    name ="MSG_AVATAR_CRYPTKEY",
  },
  [0xa641] = {
    name ="MSG_AVATAR_DELGUILD",
  },
  [0xb841] = {
    name ="MSG_AVATAR_REMOVE_GUILD",
  },
  [0x5c42] = {
    name ="MSG_AVATAR_TEST_ITEMS",
  },
  [0x9340] = {
    name ="MSG_BANDAGE",
  },
  [0x1142] = {
    name ="MSG_BAZAAR_MANAGE",
  },
  [0xa640] = {
    name ="MSG_BCAST_TEXT",
  },
  [0x8c41] = {
    name ="MSG_BECOMENPC",
  },
  [0x2541] = {
    name ="MSG_BEG",
  },
  [0xe640] = {
    name ="MSG_BEGIN_TRADE",
  },
  [0xaa41] = {
    name ="MSG_BERSERK_OFF",
  },
  [0xa941] = {
    name ="MSG_BERSERK_ON",
  },
  [0x4942] = {
    name ="MSG_BOOT_PC",
  },
  [0xd240] = {
    name ="MSG_BUFF",
  },
  [0x2042] = {
    name ="MSG_BUFF_OTHER_GROUP",
  },
  [0x2442] = {
    name ="MSG_BUY_TRADERITEM",
  },
  [0x3841] = {
    name ="MSG_CALC_EXP",
  },
  [0x0742] = {
    name ="MSG_CAMP",
  },
  [0xd040] = {
    name ="MSG_CANCEL_DUEL",
  },
  [0x5a41] = {
    name ="MSG_CANCEL_SNEAKHIDE",
  },
  [0xdb40] = {
    name ="MSG_CANCEL_TRADE",
  },
  [0x7e41] = {
    name ="MSG_CAST_SPELL",
  },
  [0x9140] = {
    name ="MSG_CHANGE_FORM",
  },
  [0x9541] = {
    name ="MSG_CHANGE_GUILDLEADER",
  },
  [0x5841] = {
    name ="MSG_CHANGE_MEDITATE",
  },
  [0xcb40] = {
    name ="MSG_CHANGE_NAME",
  },
  [0x3241] = {
    name ="MSG_CHANGE_PCAFFECT",
  },
  [0x7140] = {
    name ="MSG_CHANNEL_STATUS",
  },
  [0x1042] = {
    name ="MSG_CHATMSG",
  },
  [0x0980] = {
    name ="MSG_CHAT_ADDRESS",
  },
  [0x2970] = {
    name ="MSG_CHAT_BCAST",
  },
  [0x3b70] = {
    name ="MSG_CHAT_REPOP_ZONE",
  },
  [0x2842] = {
    name ="MSG_CHAT_WORLD_KICK",
  },
  [0x3441] = {
    name ="MSG_CHEATER",
  },
  [0x6d41] = {
    name ="MSG_CHEATER_NOTIFY",
  },
  [0x6942] = {
    name ="MSG_CHECK_COMMAND",
  },
  [0x3c40] = {
    name ="MSG_CHECK_GIVE",
  },
  [0xc841] = {
    name ="MSG_CHECK_ITEMS",
  },
  [0x3742] = {
    name ="MSG_CHECK_ITEMS_ZONE",
  },
  [0xd740] = {
    name ="MSG_CHEST_LOCK",
  },
  [0x4e41] = {
    name ="MSG_CLEAR_FACTIONTABLE",
  },
  [0x0542] = {
    name ="MSG_CLEAR_WORLD_CON",
  },
  [0x2c20] = {
    name ="MSG_CLIENTWASLINKDEAD",
  },
  [0xae40] = {
    name ="MSG_CLIENT_HANDOVER_PC",
  },
  [0x0680] = {
    name ="MSG_CLIENT_RECONNECTING",
  },
  [0xa540] = {
    name ="MSG_CLIENT_SPAWN_NPC",
  },
  [0x2441] = {
    name ="MSG_CLIENT_SPAWN_PCONTROL_NPC",
  },
  [0x2341] = {
    name ="MSG_CMD_INDEX",
  },
  [0xb940] = {
    name ="MSG_COMBINE",
  },
  [0xba40] = {
    name ="MSG_COMBINE_ITEM",
  },
  [0xf641] = {
    name ="MSG_COMP_INITITEMS",
  },
  [0xf741] = {
    name ="MSG_COMP_INITSWITCHES",
  },
  [0x0810] = {
    name ="MSG_CONNECTING",
  },
  [0xb740] = {
    name ="MSG_CONSENT",
  },
  [0xb840] = {
    name ="MSG_CONSENT_LOOT",
  },
  [0xd540] = {
    name ="MSG_CONSENT_VERIFY",
  },
  [0x0210] = {
    name ="MSG_CONTINUE",
  },
  [0x9740] = {
    name ="MSG_CONTINUE_ROUTE",
  },
  [0x2641] = {
    name ="MSG_CONTROL_NPC",
  },
  [0xbe40] = {
    name ="MSG_CONTROL_PLAYER",
  },
  [0xd741] = {
    name ="MSG_CORPSELOG",
  },
  [0x2140] = {
    name ="MSG_CORPSE_XYZ",
  },
  [0x3520] = {
    name ="MSG_CPLAYER_DIED",
  },
  [0x2e20] = {
    name ="MSG_CPLAYER_LOGIN",
  },
  [0x2f20] = {
    name ="MSG_CPLAYER_LOGOUT",
  },
  [0x3020] = {
    name ="MSG_CPLAYER_STATUS",
  },
  [0x2370] = {
    name ="MSG_CREATE_ACCOUNT",
  },
  [0x3f41] = {
    name ="MSG_CREATE_GOLD",
  },
  [0x3e20] = {
    name ="MSG_CREATE_GROUP",
  },
  [0x3d20] = {
    name ="MSG_CREATE_GROUP_RESPONSE",
  },
  [0x2b41] = {
    name ="MSG_CREATE_GUILD",
  },
  [0x5e40] = {
    name ="MSG_CREATE_ITEM",
  },
  [0xe740] = {
    name ="MSG_CREATE_PPOINT",
  },
  [0x5f42] = {
    name ="MSG_CS_RAID",
  },
  [0x8341] = {
    name ="MSG_CURHP",
  },
  [0xff40] = {
    name ="MSG_DEBUG_COMBAT",
  },
  [0xcd40] = {
    name ="MSG_DEBUG_NPC",
  },
  [0xfc41] = {
    name ="MSG_DEBUG_NPC_HATE",
  },
  [0x3e42] = {
    name ="MSG_DEBUG_REQUEST",
  },
  [0x3720] = {
    name ="MSG_DELETE_ALL_CORPSES",
  },
  [0xb441] = {
    name ="MSG_DELETE_BITEM",
  },
  [0xb541] = {
    name ="MSG_DELETE_BMONEY",
  },
  [0xe941] = {
    name ="MSG_DELETE_CORPSE",
  },
  [0x1a41] = {
    name ="MSG_DELETE_GUILD",
  },
  [0xae41] = {
    name ="MSG_DELETE_IITEM",
  },
  [0xb041] = {
    name ="MSG_DELETE_IMONEY",
  },
  [0xe840] = {
    name ="MSG_DELETE_PPOINT",
  },
  [0xef40] = {
    name ="MSG_DELETE_ROUTE",
  },
  [0x4a42] = {
    name ="MSG_DELETE_SPELL",
  },
  [0x8840] = {
    name ="MSG_DELETE_ZCMD",
  },
  [0xa441] = {
    name ="MSG_DELTRACELOGIN",
  },
  [0x2b40] = {
    name ="MSG_DEL_ILIST",
  },
  [0x7d40] = {
    name ="MSG_DEL_INVENTORY",
  },
  [0x0840] = {
    name ="MSG_DEL_MLIST",
  },
  [0x0d41] = {
    name ="MSG_DEL_MSG",
  },
  [0x5a40] = {
    name ="MSG_DEL_PC",
  },
  [0x2e41] = {
    name ="MSG_DEPOP_NPC",
  },
  [0xb140] = {
    name ="MSG_DEPOP_ZONE",
  },
  [0x6842] = {
    name ="MSG_DEVTUNE_NPC",
  },
  [0xaa40] = {
    name ="MSG_DISARM",
  },
  [0xf341] = {
    name ="MSG_DISARMTRAPS",
  },
  [0xab40] = {
    name ="MSG_DISARM_RESULT",
  },
  [0x9741] = {
    name ="MSG_DISBAND",
  },
  [0xe641] = {
    name ="MSG_DISCIPLINE",
  },
  [0xf241] = {
    name ="MSG_DISCIPLINE_CHANGE",
  },
  [0x0910] = {
    name ="MSG_DISCONNECTING",
  },
  [0x5d42] = {
    name ="MSG_DISPLAY_QUEST_FLAGS",
  },
  [0x6041] = {
    name ="MSG_DOATTACK",
  },
  [0x4070] = {
    name ="MSG_DOES_NAME_EXIST",
  },
  [0x3420] = {
    name ="MSG_DOPLAYERSTATCOUNT",
  },
  [0xdc40] = {
    name ="MSG_DO_TRADE",
  },
  [0xcf40] = {
    name ="MSG_DUEL",
  },
  [0x5e41] = {
    name ="MSG_DUEL_END",
  },
  [0x5d41] = {
    name ="MSG_DUEL_START",
  },
  [0x5f40] = {
    name ="MSG_DUST_CONFIRM",
  },
  [0x4c40] = {
    name ="MSG_DUST_CORPSE",
  },
  [0x0a10] = {
    name ="MSG_ECHO",
  },
  [0x2670] = {
    name ="MSG_ECHOREPLY",
  },
  [0x2570] = {
    name ="MSG_ECHOREQUEST",
  },
  [0xe141] = {
    name ="MSG_EMOTE_WORLD",
  },
  [0xe341] = {
    name ="MSG_EMOTE_ZONE",
  },
  [0xe541] = {
    name ="MSG_ENCRYPTKEY",
  },
  [0xee40] = {
    name ="MSG_END_ROUTE",
  },
  [0x1e40] = {
    name ="MSG_ENVIRON_DMG",
  },
  [0x4540] = {
    name ="MSG_EQ_ADDMISSILE",
  },
  [0x2840] = {
    name ="MSG_EQ_ADDPLAYER",
  },
  [0x4640] = {
    name ="MSG_EQ_MISSILEHIT",
  },
  [0x6b42] = {
    name ="MSG_EQ_NETPLAYER",
  },
  [0x5f41] = {
    name ="MSG_EQ_NETPLAYERBUFF",
  },
  [0x2940] = {
    name ="MSG_EQ_RMPLAYER",
  },
  [0x2a40] = {
    name ="MSG_EQ_UPDATEPLAYER",
  },
  [0x4841] = {
    name ="MSG_EXCEPTION",
  },
  [0x3941] = {
    name ="MSG_EXEFILE_CHECK",
  },
  [0x9041] = {
    name ="MSG_EXPENDITEMCHARGE",
  },
  [0x2941] = {
    name ="MSG_EXPLOST",
  },
  [0x9941] = {
    name ="MSG_EXPUP",
  },
  [0xf541] = {
    name ="MSG_EXTRA_UPDATE_TARGET",
  },
  [0x6840] = {
    name ="MSG_FACTION_NAME",
  },
  [0xac40] = {
    name ="MSG_FEIGNDEATH",
  },
  [0x2440] = {
    name ="MSG_FELLTHRUWORLD",
  },
  [0x2340] = {
    name ="MSG_FINALQUIT",
  },
  [0xd340] = {
    name ="MSG_FINAL_INVENTORY",
  },
  [0x0341] = {
    name ="MSG_FINAL_MONEY",
  },
  [0x6940] = {
    name ="MSG_FIND_PLAYER",
  },
  [0x8f41] = {
    name ="MSG_FISH",
  },
  [0x5641] = {
    name ="MSG_FOOD_CHARGE",
  },
  [0x9440] = {
    name ="MSG_FORAGE",
  },
  [0xb641] = {
    name ="MSG_FORCE_BDELITEM",
  },
  [0xb741] = {
    name ="MSG_FORCE_BDELMONEY",
  },
  [0xb241] = {
    name ="MSG_FORCE_DELITEM",
  },
  [0xb341] = {
    name ="MSG_FORCE_DELMONEY",
  },
  [0x0620] = {
    name ="MSG_FORCE_DUST",
  },
  [0x3842] = {
    name ="MSG_FORCE_TITLE",
  },
  [0xc840] = {
    name ="MSG_FORM_CHANGED",
  },
  [0xd941] = {
    name ="MSG_FOUND_CORPSE",
  },
  [0xbc40] = {
    name ="MSG_FOUND_PLAYER",
  },
  [0xdf41] = {
    name ="MSG_FREEGUILDLOCK",
  },
  [0x6a40] = {
    name ="MSG_FREEZE_PLAYER",
  },
  [0xc541] = {
    name ="MSG_FRIENDS_LIST",
  },
  [0xc641] = {
    name ="MSG_FTELL",
  },
  [0x5741] = {
    name ="MSG_FWATER_UPDATE",
  },
  [0xa541] = {
    name ="MSG_GETGUILDLIST",
  },
  [0x3741] = {
    name ="MSG_GETNPC_REACTION",
  },
  [0xe041] = {
    name ="MSG_GETSTATS",
  },
  [0x3442] = {
    name ="MSG_GET_CORPSE_INFO",
  },
  [0x2f41] = {
    name ="MSG_GET_ITEM_NAMES",
  },
  [0x4f41] = {
    name ="MSG_GET_SAFECOORDS",
  },
  [0xd041] = {
    name ="MSG_GET_SOULMARKS",
  },
  [0x1020] = {
    name ="MSG_GET_VEHICLE_ZONE",
  },
  [0xaf41] = {
    name ="MSG_GIVE_IITEM",
  },
  [0xb141] = {
    name ="MSG_GIVE_IMONEY",
  },
  [0x3e40] = {
    name ="MSG_GIVE_ITEM",
  },
  [0x3f40] = {
    name ="MSG_GIVE_MONEY",
  },
  [0x3d40] = {
    name ="MSG_GIVE_OK",
  },
  [0x2742] = {
    name ="MSG_GMALTGIVE",
  },
  [0x4742] = {
    name ="MSG_GMDEBUG_MESSAGE",
  },
  [0xc141] = {
    name ="MSG_GMEXPGIVE",
  },
  [0xc241] = {
    name ="MSG_GMEXPSET",
  },
  [0xc041] = {
    name ="MSG_GMQUEST",
  },
  [0x3120] = {
    name ="MSG_GMSTATUS",
  },
  [0x3670] = {
    name ="MSG_GMSTATUSNEW",
  },
  [0x1940] = {
    name ="MSG_GOSSIP",
  },
  [0x6e40] = {
    name ="MSG_GOTO_PLAYER",
  },
  [0xd440] = {
    name ="MSG_GRANT_TITLE",
  },
  [0x4340] = {
    name ="MSG_GROUP",
  },
  [0x1740] = {
    name ="MSG_GSAY",
  },
  [0x9241] = {
    name ="MSG_GUILDFILE_DATA",
  },
  [0x9d40] = {
    name ="MSG_GUILDMASTER_GOODBYE",
  },
  [0x0442] = {
    name ="MSG_GUILDMOTD",
  },
  [0x0342] = {
    name ="MSG_GUILDMOTD_SET",
  },
  [0x7b41] = {
    name ="MSG_GUILD_ADDED",
  },
  [0x2741] = {
    name ="MSG_GUILD_EXISTS",
  },
  [0x1e41] = {
    name ="MSG_GUILD_LIST",
  },
  [0x3370] = {
    name ="MSG_GUILD_OWNERSHIP",
  },
  [0x9141] = {
    name ="MSG_GUILD_PEACE",
  },
  [0x1841] = {
    name ="MSG_GUILD_REPLY",
  },
  [0x1f41] = {
    name ="MSG_GUILD_SAY",
  },
  [0x1c41] = {
    name ="MSG_GUILD_STATUS",
  },
  [0x6f41] = {
    name ="MSG_GUILD_WAR",
  },
  [0x0c10] = {
    name ="MSG_HANDLE_IN_USE",
  },
  [0xc940] = {
    name ="MSG_HARMLESS_CLEAR",
  },
  [0x7840] = {
    name ="MSG_HARMLESS_SET",
  },
  [0x0e41] = {
    name ="MSG_HDRS_SENT",
  },
  [0x8641] = {
    name ="MSG_HIDE",
  },
  [0xd441] = {
    name ="MSG_HIDEME",
  },
  [0xb240] = {
    name ="MSG_HITPOINT_UPDATE",
  },
  [0x1241] = {
    name ="MSG_HOUSE_ITEM",
  },
  [0x1041] = {
    name ="MSG_HOUSE_LOCK",
  },
  [0x1141] = {
    name ="MSG_HOUSE_MONEY",
  },
  [0x8440] = {
    name ="MSG_INIT_ENCTABLE",
  },
  [0x6740] = {
    name ="MSG_INIT_FACTION",
  },
  [0x7740] = {
    name ="MSG_INIT_ITLIST",
  },
  [0x7440] = {
    name ="MSG_INIT_TRCLASS",
  },
  [0xb640] = {
    name ="MSG_INSPECT",
  },
  [0x9c41] = {
    name ="MSG_INTIMIDATE",
  },
  [0x0410] = {
    name ="MSG_INVALID_ID",
  },
  [0x0510] = {
    name ="MSG_INVALID_PASSWD",
  },
  [0x4040] = {
    name ="MSG_INVITE",
  },
  [0x1741] = {
    name ="MSG_INVITE_GUILD",
  },
  [0x4240] = {
    name ="MSG_INVITE_OK",
  },
  [0x5c41] = {
    name ="MSG_INVULNERABLE_AVATAR",
  },
  [0xf840] = {
    name ="MSG_ITEM_ENC",
  },
  [0x4642] = {
    name ="MSG_ITEM_FIND",
  },
  [0x2040] = {
    name ="MSG_JUMP",
  },
  [0x1c40] = {
    name ="MSG_KICKFROMWORLD",
  },
  [0x6d40] = {
    name ="MSG_KICK_PLAYER",
  },
  [0x6c40] = {
    name ="MSG_KILL_PLAYER",
  },
  [0xd841] = {
    name ="MSG_KUNARK",
  },
  [0x6e41] = {
    name ="MSG_LAST_NAME",
  },
  [0x8241] = {
    name ="MSG_LAUNCHSPELL_INFO",
  },
  [0x9841] = {
    name ="MSG_LEVELUP",
  },
  [0xf041] = {
    name ="MSG_LFG",
  },
  [0x9a41] = {
    name ="MSG_LIMBOMONEY",
  },
  [0x7941] = {
    name ="MSG_LIMBO_ICON",
  },
  [0x7841] = {
    name ="MSG_LIMBO_IEQ",
  },
  [0x7a41] = {
    name ="MSG_LIMBO_INOTES",
  },
  [0x1d41] = {
    name ="MSG_LIST_GUILD",
  },
  [0x3770] = {
    name ="MSG_LOADAVATAR",
  },
  [0x1240] = {
    name ="MSG_LOAD_AVATARS",
  },
  [0x1340] = {
    name ="MSG_LOAD_CHECKSUMS",
  },
  [0x8240] = {
    name ="MSG_LOAD_ENCTABLE",
  },
  [0x6540] = {
    name ="MSG_LOAD_FACTION",
  },
  [0x7540] = {
    name ="MSG_LOAD_ITLIST",
  },
  [0x6040] = {
    name ="MSG_LOAD_NPC",
  },
  [0x8f40] = {
    name ="MSG_LOAD_TEXTFILE",
  },
  [0x7240] = {
    name ="MSG_LOAD_TRCLASS",
  },
  [0x8540] = {
    name ="MSG_LOAD_ZCMD",
  },
  [0x4242] = {
    name ="MSG_LOCALE",
  },
  [0x0e20] = {
    name ="MSG_LOCATE_VEHICLE",
  },
  [0x5040] = {
    name ="MSG_LOCKED_CORPSE",
  },
  [0x3b40] = {
    name ="MSG_LOCKED_MERCHANT",
  },
  [0x4e40] = {
    name ="MSG_LOCK_CORPSE",
  },
  [0x3940] = {
    name ="MSG_LOCK_MERCHANT",
  },
  [0x3c70] = {
    name ="MSG_LOGINLIST",
  },
  [0x3f70] = {
    name ="MSG_LOGINSERVER",
  },
  [0xfd40] = {
    name ="MSG_LOGIN_KEYCODE",
  },
  [0x0e10] = {
    name ="MSG_LOGIN_REQUEST",
  },
  [0xcc41] = {
    name ="MSG_LOGME_CHEATER",
  },
  [0x3d70] = {
    name ="MSG_LOGOUTLIST",
  },
  [0x3570] = {
    name ="MSG_LOGOUTSTATUS",
  },
  [0xd940] = {
    name ="MSG_LOGOUT_PLAYER",
  },
  [0xfb41] = {
    name ="MSG_LOGSHOWEQ",
  },
  [0xa040] = {
    name ="MSG_LOOT_SLOT",
  },
  [0x7c41] = {
    name ="MSG_MAKENEW_GUILDLEADER",
  },
  [0x9441] = {
    name ="MSG_MAKE_PEACE",
  },
  [0x9341] = {
    name ="MSG_MAKE_WAR",
  },
  [0x9240] = {
    name ="MSG_MATERIAL_SWAP",
  },
  [0x9d41] = {
    name ="MSG_MEND",
  },
  [0x3540] = {
    name ="MSG_MERCHANT_BUY",
  },
  [0x3840] = {
    name ="MSG_MERCHANT_CLEARSLOT",
  },
  [0x3740] = {
    name ="MSG_MERCHANT_GOODBYE",
  },
  [0x2740] = {
    name ="MSG_MERCHANT_SELL",
  },
  [0x8940] = {
    name ="MSG_MODIFY_ZCMD",
  },
  [0x7b40] = {
    name ="MSG_MOD_INVENTORY",
  },
  [0x6240] = {
    name ="MSG_MOD_ROUTE",
  },
  [0xe441] = {
    name ="MSG_MOVELOG",
  },
  [0x4741] = {
    name ="MSG_MOVE_CHARGE",
  },
  [0x2c41] = {
    name ="MSG_MOVE_ITEM",
  },
  [0x2d41] = {
    name ="MSG_MOVE_MONEY",
  },
  [0xa440] = {
    name ="MSG_MOVE_PPOINT",
  },
  [0x8c40] = {
    name ="MSG_NAME_APPROVE",
  },
  [0xcc40] = {
    name ="MSG_NAME_CHANGED",
  },
  [0x8b40] = {
    name ="MSG_NAME_SUBMIT",
  },
  [0x4940] = {
    name ="MSG_NEW_PC",
  },
  [0x0741] = {
    name ="MSG_NEW_TEXT",
  },
  [0x1920] = {
    name ="MSG_NEW_TEXT_RESPONSE",
  },
  [0xce40] = {
    name ="MSG_NOTE_TEXT",
  },
  [0xef41] = {
    name ="MSG_NO_NAME_APPROVAL",
  },
  [0x3920] = {
    name ="MSG_NPC_BCAST",
  },
  [0x0820] = {
    name ="MSG_NPC_CORPSE",
  },
  [0xf740] = {
    name ="MSG_NPC_ENC",
  },
  [0x7e40] = {
    name ="MSG_NPC_ITEM",
  },
  [0x7f40] = {
    name ="MSG_NPC_MONEY",
  },
  [0x0242] = {
    name ="MSG_NPC_REPOP_ZONE",
  },
  [0x5e42] = {
    name ="MSG_NPC_SAY_TEXT",
  },
  [0x3a70] = {
    name ="MSG_NUMMONSTERS_INWORLD",
  },
  [0x1f70] = {
    name ="MSG_NUMPLAYERS_INWORLD",
  },
  [0x2070] = {
    name ="MSG_NUMPLAYERS_VALIDATE_ACCOUNTKEY",
  },
  [0xbc41] = {
    name ="MSG_OFFVEHICLE",
  },
  [0xbb41] = {
    name ="MSG_ONVEHICLE",
  },
  [0x1b40] = {
    name ="MSG_OOC",
  },
  [0x3942] = {
    name ="MSG_OVERRIDE_TIMER",
  },
  [0x9a40] = {
    name ="MSG_PARTY_EXPERIENCE",
  },
  [0xbb40] = {
    name ="MSG_PARTY_NAMES",
  },
  [0x0010] = {
    name ="MSG_PASS",
  },
  [0xea40] = {
    name ="MSG_PASS_ITEMS",
  },
  [0x2520] = {
    name ="MSG_PCGUILD_UPDATE",
  },
  [0x2242] = {
    name ="MSG_PC_MONSTER_OK",
  },
  [0x0380] = {
    name ="MSG_PC_RECEIVED",
  },
  [0x5941] = {
    name ="MSG_PC_TRANSFERRED",
  },
  [0xac41] = {
    name ="MSG_PERMAKILL",
  },
  [0x4542] = {
    name ="MSG_PET_COMMAND",
  },
  [0x0141] = {
    name ="MSG_PKILL_CLEAR",
  },
  [0x0041] = {
    name ="MSG_PKILL_SET",
  },
  [0xbf40] = {
    name ="MSG_PLAYER_CONTROLLED",
  },
  [0x4a40] = {
    name ="MSG_PLAYER_DIED",
  },
  [0xbd40] = {
    name ="MSG_PLAYER_FROZEN",
  },
  [0xc440] = {
    name ="MSG_PLAYER_GONETO",
  },
  [0xc340] = {
    name ="MSG_PLAYER_KILLED",
  },
  [0x3620] = {
    name ="MSG_PLAYER_LOGOUT",
  },
  [0xc640] = {
    name ="MSG_PLAYER_SUMMONED",
  },
  [0xc240] = {
    name ="MSG_PLAYER_UNCONTROLLED",
  },
  [0xc040] = {
    name ="MSG_PLAYER_UNFROZEN",
  },
  [0xa140] = {
    name ="MSG_PLAY_ANIM",
  },
  [0x0142] = {
    name ="MSG_PLAY_MUSICTRACK",
  },
  [0x4840] = {
    name ="MSG_PLAY_SOUND",
  },
  [0x0c41] = {
    name ="MSG_POST_MSG",
  },
  [0x9e41] = {
    name ="MSG_PQ_CHECKIN",
  },
  [0x8e41] = {
    name ="MSG_PQ_CHECKOUT",
  },
  [0xa041] = {
    name ="MSG_PQ_DELETE",
  },
  [0xa141] = {
    name ="MSG_PQ_LOGTOBUG",
  },
  [0xa241] = {
    name ="MSG_PQ_LOGTOFEED",
  },
  [0xa341] = {
    name ="MSG_PQ_LOGTOGUIDE",
  },
  [0x9f41] = {
    name ="MSG_PQ_UNDO_CHECKOUT",
  },
  [0x0f40] = {
    name ="MSG_PQ_UPDATE",
  },
  [0x0641] = {
    name ="MSG_PRESERVE_CORPSE",
  },
  [0x6141] = {
    name ="MSG_PRIMARY_TOGGLE",
  },
  [0x2540] = {
    name ="MSG_PROHIBITEXES",
  },
  [0x2b20] = {
    name ="MSG_PUTCPLAYERINZONE",
  },
  [0xee41] = {
    name ="MSG_QUERY_EXP",
  },
  [0x8140] = {
    name ="MSG_QUEST_ITEM",
  },
  [0xcf41] = {
    name ="MSG_QUEST_PKILL",
  },
  [0x8040] = {
    name ="MSG_QUEST_REWARD",
  },
  [0x5041] = {
    name ="MSG_QUIT_GAME",
  },
  [0xe741] = {
    name ="MSG_RANDOMNUM",
  },
  [0x1640] = {
    name ="MSG_RANDOM_RETURN",
  },
  [0x6341] = {
    name ="MSG_RDPSTAT",
  },
  [0xd840] = {
    name ="MSG_READY_ENTER_WORLD",
  },
  [0xda40] = {
    name ="MSG_READY_TRADE",
  },
  [0xeb40] = {
    name ="MSG_REC_ITEMS",
  },
  [0xd640] = {
    name ="MSG_REFUSE_TRADE",
  },
  [0x8141] = {
    name ="MSG_REJECT_ADDPLAYER",
  },
  [0x1d40] = {
    name ="MSG_REJECT_PC",
  },
  [0x4441] = {
    name ="MSG_RELEASE_GM",
  },
  [0x4541] = {
    name ="MSG_RELEASE_LOOT",
  },
  [0x4641] = {
    name ="MSG_RELEASE_MERCHANT",
  },
  [0x0880] = {
    name ="MSG_RELEASE_PLAYER_AFTER_TIMEOUT",
  },
  [0x1b20] = {
    name ="MSG_RELOAD_GUILDFILE",
  },
  [0x1c20] = {
    name ="MSG_REMOVE_CHEATER",
  },
  [0x1941] = {
    name ="MSG_REMOVE_GUILD",
  },
  [0x4270] = {
    name ="MSG_REMOVE_NAME",
  },
  [0x8a40] = {
    name ="MSG_REMOVE_ZCMD",
  },
  [0xb941] = {
    name ="MSG_RENAME_GUILD",
  },
  [0xf040] = {
    name ="MSG_REPOP_PPOINTS",
  },
  [0x8740] = {
    name ="MSG_REPOP_ZCMD",
  },
  [0xbd41] = {
    name ="MSG_REPORT_TEXT",
  },
  [0x5a42] = {
    name ="MSG_REPORT_TEXT_RAW",
  },
  [0x1420] = {
    name ="MSG_REQCHESTITEMWAFFECT",
  },
  [0x0d20] = {
    name ="MSG_REQITEMWAFFECT",
  },
  [0x4941] = {
    name ="MSG_REQUEST_ITEM",
  },
  [0x1140] = {
    name ="MSG_REQUEST_PETITIONS",
  },
  [0xfe41] = {
    name ="MSG_REQUEST_TARGET",
  },
  [0x0842] = {
    name ="MSG_REQUEST_ZONE",
  },
  [0x1720] = {
    name ="MSG_REQ_AVATAR",
  },
  [0x0920] = {
    name ="MSG_REQ_CORPSEITEM",
  },
  [0x5140] = {
    name ="MSG_REQ_CORPSEITEMS",
  },
  [0x1220] = {
    name ="MSG_REQ_FACTIONTABLE",
  },
  [0x9c40] = {
    name ="MSG_REQ_GUILDMASTER",
  },
  [0x2841] = {
    name ="MSG_REQ_GUILDNAME",
  },
  [0x1b41] = {
    name ="MSG_REQ_GUILD_STATUS",
  },
  [0x0841] = {
    name ="MSG_REQ_HDR",
  },
  [0x0f41] = {
    name ="MSG_REQ_HOUSELOCK",
  },
  [0xb540] = {
    name ="MSG_REQ_INSPECT",
  },
  [0x0320] = {
    name ="MSG_REQ_ITEM",
  },
  [0xe940] = {
    name ="MSG_REQ_ITEMS",
  },
  [0x1541] = {
    name ="MSG_REQ_KEYNUMBER",
  },
  [0x1441] = {
    name ="MSG_REQ_LOOTERS",
  },
  [0x0b40] = {
    name ="MSG_REQ_MERCHANTITEMS",
  },
  [0x0941] = {
    name ="MSG_REQ_MSG",
  },
  [0x0120] = {
    name ="MSG_REQ_NPC",
  },
  [0x0720] = {
    name ="MSG_REQ_PLAYERS",
  },
  [0x4b40] = {
    name ="MSG_REQ_REPOP",
  },
  [0x2041] = {
    name ="MSG_REQ_SPELLCAST",
  },
  [0x1641] = {
    name ="MSG_REQ_SWITCHNAME",
  },
  [0x5940] = {
    name ="MSG_REQ_THETIME",
  },
  [0x3041] = {
    name ="MSG_REQ_TIME_PLAYED",
  },
  [0xd140] = {
    name ="MSG_REQ_TRADE",
  },
  [0x1642] = {
    name ="MSG_REQ_TRADERITEMS",
  },
  [0x2642] = {
    name ="MSG_REQ_VERSION",
  },
  [0xf440] = {
    name ="MSG_REQ_WHO",
  },
  [0x6442] = {
    name ="MSG_REQUEST_INSPECT_ITEM",
  },
  [0x3b41] = {
    name ="MSG_RESCUE",
  },
  [0x4141] = {
    name ="MSG_RESEND_ADDPLAYER",
  },
  [0x3d42] = {
    name ="MSG_RESET_ACTIVATED_SKILL",
  },
  [0x6a42] = {
    name ="MSG_RESET_MODULATION_TIMER",
  },
  [0xf941] = {
    name ="MSG_RESET_PMONEY",
  },
  [0x3a42] = {
    name ="MSG_RESTORE_FACTION",
  },
  [0xc941] = {
    name ="MSG_RESTORE_PC",
  },
  [0x2a41] = {
    name ="MSG_RESURRECT",
  },
  [0xec41] = {
    name ="MSG_RESURRECT_COMPLETE",
  },
  [0xeb41] = {
    name ="MSG_RESURRECT_PENDING",
  },
  [0x2240] = {
    name ="MSG_RESURRECT_REJECT",
  },
  [0x9b41] = {
    name ="MSG_RESURRECT_RESPONSE",
  },
  [0xf940] = {
    name ="MSG_RETURN_CHEST_ITEMS",
  },
  [0x9b40] = {
    name ="MSG_RM_SWITCH",
  },
  [0x1f40] = {
    name ="MSG_RUN",
  },
  [0x3a41] = {
    name ="MSG_RUNSPELL_CHECK",
  },
  [0xea41] = {
    name ="MSG_SACRIFICE",
  },
  [0xab41] = {
    name ="MSG_SAFE_FALL",
  },
  [0x5341] = {
    name ="MSG_SAVEDEADPC",
  },
  [0x5441] = {
    name ="MSG_SAVEREPOP_PC",
  },
  [0x5541] = {
    name ="MSG_SAVEZONE_PC",
  },
  [0x6440] = {
    name ="MSG_SAVE_CON",
  },
  [0x8340] = {
    name ="MSG_SAVE_ENCTABLE",
  },
  [0x6340] = {
    name ="MSG_SAVE_EQ",
  },
  [0x6640] = {
    name ="MSG_SAVE_FACTION",
  },
  [0x1320] = {
    name ="MSG_SAVE_FACTIONTABLE",
  },
  [0x7640] = {
    name ="MSG_SAVE_ITLIST",
  },
  [0x9840] = {
    name ="MSG_SAVE_NOTE",
  },
  [0x6140] = {
    name ="MSG_SAVE_NPC",
  },
  [0x2e40] = {
    name ="MSG_SAVE_PC",
  },
  [0xf140] = {
    name ="MSG_SAVE_ROUTES",
  },
  [0xd141] = {
    name ="MSG_SAVE_SOULMARKS",
  },
  [0x9040] = {
    name ="MSG_SAVE_TEXTFILE",
  },
  [0x7340] = {
    name ="MSG_SAVE_TRCLASS",
  },
  [0x8640] = {
    name ="MSG_SAVE_ZCMD",
  },
  [0x6042] = {
    name ="MSG_SC_RAID",
  },
  [0x5b42] = {
    name ="MSG_SCRIPT_COMMAND",
  },
  [0xa741] = {
    name ="MSG_SEARCH_CORPSE",
  },
  [0x5141] = {
    name ="MSG_SECONDARY_TOGGLE",
  },
  [0x0180] = {
    name ="MSG_SELECT_CHARACTER",
  },
  [0x0a20] = {
    name ="MSG_SENDCORPSE_EQ",
  },
  [0x9e40] = {
    name ="MSG_SENDPC_EQ",
  },
  [0x1520] = {
    name ="MSG_SENDPC_WEQ",
  },
  [0x4740] = {
    name ="MSG_SEND_CHARACTERS",
  },
  [0x0a41] = {
    name ="MSG_SEND_HDR",
  },
  [0x7c40] = {
    name ="MSG_SEND_INVENTORY",
  },
  [0x0441] = {
    name ="MSG_SEND_MONEY",
  },
  [0x0b41] = {
    name ="MSG_SEND_MSG",
  },
  [0x3c42] = {
    name ="MSG_SEND_PAGE_UPDATE",
  },
  [0x3640] = {
    name ="MSG_SEND_PC",
  },
  [0x8741] = {
    name ="MSG_SENSEDIRECTION",
  },
  [0x8841] = {
    name ="MSG_SENSETRAPS",
  },
  [0x2d20] = {
    name ="MSG_SERVERNAME",
  },
  [0x6f40] = {
    name ="MSG_SET_AVATAR",
  },
  [0xe841] = {
    name ="MSG_SET_DATARATE",
  },
  [0xfd41] = {
    name ="MSG_SET_FACTIONTABLE",
  },
  [0xdc41] = {
    name ="MSG_SET_MOTD",
  },
  [0x4b42] = {
    name ="MSG_SHIELD_PLAYER",
  },
  [0x1840] = {
    name ="MSG_SHOUT",
  },
  [0x0942] = {
    name ="MSG_SHOWINVISSHOUTS",
  },
  [0x3220] = {
    name ="MSG_SHUTDOWN_ALL",
  },
  [0xc740] = {
    name ="MSG_SILENCE_CLEAR",
  },
  [0x7940] = {
    name ="MSG_SILENCE_SET",
  },
  [0xd641] = {
    name ="MSG_SISALOG",
  },
  [0x8941] = {
    name ="MSG_SKILLIMPROVE",
  },
  [0xbe41] = {
    name ="MSG_SKILL_CHANGE",
  },
  [0x9641] = {
    name ="MSG_SKILL_IMPROVE",
  },
  [0x8d41] = {
    name ="MSG_SKY",
  },
  [0x5340] = {
    name ="MSG_SND_CORPSE_CON",
  },
  [0x5240] = {
    name ="MSG_SND_CORPSE_EQ",
  },
  [0x5540] = {
    name ="MSG_SND_CORPSE_KEY",
  },
  [0x5740] = {
    name ="MSG_SND_CORPSE_MAP",
  },
  [0x5640] = {
    name ="MSG_SND_CORPSE_NOTES",
  },
  [0x5440] = {
    name ="MSG_SND_CORPSE_SB",
  },
  [0x3040] = {
    name ="MSG_SND_ICON",
  },
  [0x6741] = {
    name ="MSG_SND_ICON_CRC",
  },
  [0x3140] = {
    name ="MSG_SND_IEQ",
  },
  [0x6841] = {
    name ="MSG_SND_IEQ_CRC",
  },
  [0x3340] = {
    name ="MSG_SND_IKEY",
  },
  [0x2f40] = {
    name ="MSG_SND_IMAP",
  },
  [0x3440] = {
    name ="MSG_SND_INOTES",
  },
  [0x6941] = {
    name ="MSG_SND_INOTES_CRC",
  },
  [0x3240] = {
    name ="MSG_SND_ISBOOK",
  },
  [0x0420] = {
    name ="MSG_SND_ITEM",
  },
  [0x0c40] = {
    name ="MSG_SND_MERCHANT_EQ",
  },
  [0x0940] = {
    name ="MSG_SND_MONEY",
  },
  [0x0220] = {
    name ="MSG_SND_NPC",
  },
  [0x0240] = {
    name ="MSG_SND_PCON",
  },
  [0x0340] = {
    name ="MSG_SND_PEQ",
  },
  [0x0540] = {
    name ="MSG_SND_PKEY",
  },
  [0x0140] = {
    name ="MSG_SND_PMAP",
  },
  [0x0640] = {
    name ="MSG_SND_PNOTES",
  },
  [0x0440] = {
    name ="MSG_SND_PSBOOK",
  },
  [0x1742] = {
    name ="MSG_SND_TRADER_EQ",
  },
  [0xfa40] = {
    name ="MSG_SND_WCON",
  },
  [0xfb40] = {
    name ="MSG_SND_WEQ",
  },
  [0xfc40] = {
    name ="MSG_SND_WNOTES",
  },
  [0x0a40] = {
    name ="MSG_SND_WOBJECTS",
  },
  [0x8541] = {
    name ="MSG_SNEAK",
  },
  [0x0241] = {
    name ="MSG_SNOOP_CLEAR",
  },
  [0x7a40] = {
    name ="MSG_SNOOP_SET",
  },
  [0x3341] = {
    name ="MSG_SNOOP_TEXT",
  },
  [0x1540] = {
    name ="MSG_SOCIAL",
  },
  [0xa841] = {
    name ="MSG_SOUL_MARK",
  },
  [0x6642] = {
    name ="MSG_SPELLACTIVATEPARTICLES",
  },
  [0x6742] = {
    name ="MSG_SPELLACTIVATEPARTICLESARRAY",
  },
  [0x2141] = {
    name ="MSG_SPELLCAST_OK",
  },
  [0x3541] = {
    name ="MSG_SPELLFILE_CHECK",
  },
  [0x4142] = {
    name ="MSG_SPELL_FIZZLE",
  },
  [0xd341] = {
    name ="MSG_SPELL_TEXT",
  },
  [0x6542] = {
    name ="MSG_SPELLWORNOFF",
  },
  [0x3141] = {
    name ="MSG_SPLIT_MONEY",
  },
  [0x6641] = {
    name ="MSG_START_ICON",
  },
  [0x6a41] = {
    name ="MSG_START_ICON_CRC",
  },
  [0x6441] = {
    name ="MSG_START_IEQ",
  },
  [0x6b41] = {
    name ="MSG_START_IEQ_CRC",
  },
  [0x6541] = {
    name ="MSG_START_INOTES",
  },
  [0x6c41] = {
    name ="MSG_START_INOTES_CRC",
  },
  [0xec40] = {
    name ="MSG_START_ROUTE",
  },
  [0xdd40] = {
    name ="MSG_START_TRADE",
  },
  [0xf540] = {
    name ="MSG_STAT_CHANGE",
  },
  [0xad40] = {
    name ="MSG_STEAL",
  },
  [0x7f41] = {
    name ="MSG_STOP_CASTING",
  },
  [0x5b41] = {
    name ="MSG_STUN_PLAYER",
  },
  [0xb340] = {
    name ="MSG_SUBMIT_BUG",
  },
  [0x3c41] = {
    name ="MSG_SUBMIT_FEEDBACK",
  },
  [0x0d10] = {
    name ="MSG_SUBMIT_REQUEST",
  },
  [0x5840] = {
    name ="MSG_SUCCESSFUL_HIT",
  },
  [0x4b41] = {
    name ="MSG_SUCCESSFUL_SKILL_USE",
  },
  [0xc540] = {
    name ="MSG_SUMMON_PLAYER",
  },
  [0xc441] = {
    name ="MSG_SURNAME",
  },
  [0xce41] = {
    name ="MSG_SWAP_SPELL",
  },
  [0x2241] = {
    name ="MSG_SWITCHSPELLNUM",
  },
  [0x8e40] = {
    name ="MSG_SWITCH_STATE",
  },
  [0x4842] = {
    name ="MSG_TAGSHOUT",
  },
  [0xb440] = {
    name ="MSG_TELEPORT_INDEX",
  },
  [0x4d41] = {
    name ="MSG_TELEPORT_PC",
  },
  [0xde41] = {
    name ="MSG_TELLTOGGLE",
  },
  [0x1440] = {
    name ="MSG_TEXT",
  },
  [0x6241] = {
    name ="MSG_TGTID",
  },
  [0x3320] = {
    name ="MSG_THREADSTATUS",
  },
  [0xf240] = {
    name ="MSG_TIME_STAMP",
  },
  [0x7040] = {
    name ="MSG_TOGGLE_CHANNEL",
  },
  [0xca40] = {
    name ="MSG_TOGGLE_PKILL",
  },
  [0x8d40] = {
    name ="MSG_TOGGLE_SWITCH",
  },
  [0x4342] = {
    name ="MSG_TOKEN_SOCIAL",
  },
  [0x3542] = {
    name ="MSG_TOKEN_TEXT",
  },
  [0x3642] = {
    name ="MSG_TOKEN_TEXT_PARAM",
  },
  [0x3e70] = {
    name ="MSG_TOUCHLIST",
  },
  [0x2640] = {
    name ="MSG_TRACELOGIN",
  },
  [0x8441] = {
    name ="MSG_TRACK",
  },
  [0x1040] = {
    name ="MSG_TRADEBUFFER_RESET",
  },
  [0x3e41] = {
    name ="MSG_TRADEFINAL_IEQ",
  },
  [0x3d41] = {
    name ="MSG_TRADEFINAL_MONEY",
  },
  [0x1842] = {
    name ="MSG_TRADER",
  },
  [0x1242] = {
    name ="MSG_TRADER_MANAGE",
  },
  [0x9640] = {
    name ="MSG_TRADE_ICON",
  },
  [0xdf40] = {
    name ="MSG_TRADE_IEQ",
  },
  [0xe240] = {
    name ="MSG_TRADE_IKEY",
  },
  [0xde40] = {
    name ="MSG_TRADE_IMAP",
  },
  [0xe340] = {
    name ="MSG_TRADE_INOTES",
  },
  [0xe040] = {
    name ="MSG_TRADE_ISBOOK",
  },
  [0xe440] = {
    name ="MSG_TRADE_MONEY",
  },
  [0x4041] = {
    name ="MSG_TRAIN",
  },
  [0x0280] = {
    name ="MSG_TRANSFER_PC",
  },
  [0x0780] = {
    name ="MSG_TRANSFER_PC_FORCED",
  },
  [0x0642] = {
    name ="MSG_TRANSLOCATE",
  },
  [0xf441] = {
    name ="MSG_TRAP_LOCATION",
  },
  [0x2a42] = {
    name ="MSG_TUNE_NPC",
  },
  [0xc140] = {
    name ="MSG_UNCONTROL_PLAYER",
  },
  [0x6b40] = {
    name ="MSG_UNFREEZE_PLAYER",
  },
  [0x4440] = {
    name ="MSG_UNGROUP",
  },
  [0x4140] = {
    name ="MSG_UNINVITE",
  },
  [0x4f40] = {
    name ="MSG_UNLOCK_CORPSE",
  },
  [0x1341] = {
    name ="MSG_UNLOCK_HOUSECHEST",
  },
  [0x3a40] = {
    name ="MSG_UNLOCK_MERCHANT",
  },
  [0x1542] = {
    name ="MSG_UPDATE_ALT_ABILS",
  },
  [0x9f40] = {
    name ="MSG_UPDATE_BUFFER",
  },
  [0xff41] = {
    name ="MSG_UPDATE_FILTERS",
  },
  [0x7d41] = {
    name ="MSG_UPDATE_LASTNAME",
  },
  [0x2542] = {
    name ="MSG_UPDATE_LUCLIN_FACE",
  },
  [0x1942] = {
    name ="MSG_UPDATE_MANA",
  },
  [0x2142] = {
    name ="MSG_UPDATE_MYCORPSE",
  },
  [0x4442] = {
    name ="MSG_UPDATE_PET_INFO",
  },
  [0xf340] = {
    name ="MSG_UPDATE_STATS",
  },
  [0x4d40] = {
    name ="MSG_UPD_CORPSE",
  },
  [0xfe40] = {
    name ="MSG_USER_CREATED",
  },
  [0x6242] = {
    name ="MSG_USER_DEL_PETITION_REQUEST",
  },
  [0x0e40] = {
    name ="MSG_USER_PETITION",
  },
  [0x6142] = {
    name ="MSG_USER_VIEW_PETITION_REQUEST",
  },
  [0x6342] = {
    name ="MSG_USER_VIEW_PETITION_RESPONSE",
  },
  [0x0f10] = {
    name ="MSG_VALID_PASSWD",
  },
  [0x0f20] = {
    name ="MSG_VEHICLE_FOUND",
  },
  [0x4a41] = {
    name ="MSG_VEHICLE_RESET",
  },
  [0xa240] = {
    name ="MSG_VEHICLE_XFR",
  },
  [0xcd41] = {
    name ="MSG_VIEW_ICON",
  },
  [0xca41] = {
    name ="MSG_VIEW_IEQ",
  },
  [0xcb41] = {
    name ="MSG_VIEW_INOTES",
  },
  [0xc741] = {
    name ="MSG_VIEW_PC",
  },
  [0x2120] = {
    name ="MSG_WCLEAR_FACTIONTABLE",
  },
  [0x8a41] = {
    name ="MSG_WEATHER",
  },
  [0x3641] = {
    name ="MSG_WEATHER_EVENT",
  },
  [0x2220] = {
    name ="MSG_WGET_SAFECOORDS",
  },
  [0x0b20] = {
    name ="MSG_WHO_RESPONSE",
  },
  [0xad41] = {
    name ="MSG_WIPE_INVENTORY",
  },
  [0x2a20] = {
    name ="MSG_WLDCLIENT_TEXT",
  },
  [0x2620] = {
    name ="MSG_WLDGROUP",
  },
  [0x3470] = {
    name ="MSG_WORLDPLAYERSTATS",
  },
  [0xed41] = {
    name ="MSG_WORLDSERVER_REJECT",
  },
  [0x3a20] = {
    name ="MSG_WORLD_REMOVE_GUILD",
  },
  [0x3b20] = {
    name ="MSG_WORLD_REMOVE_GUILD_RESPONSE",
  },
  [0x3f20] = {
    name ="MSG_WORLD_XFER",
  },
  [0x1d20] = {
    name ="MSG_WSERVER_SHUTDOWN",
  },
  [0xda41] = {
    name ="MSG_YELL",
  },
  [0x5b40] = {
    name ="MSG_ZHDR_REC",
  },
  [0x5d40] = {
    name ="MSG_ZHDR_REQ",
  },
  [0x8b41] = {
    name ="MSG_ZONECMD",
  },
  [0xdb41] = {
    name ="MSG_ZONECMDW",
  },
  [0xd541] = {
    name ="MSG_ZONECMDX",
  },
  [0x1620] = {
    name ="MSG_ZONECONTROL_PC",
  },
  [0x3820] = {
    name ="MSG_ZONEDONE_PC",
  },
  [0x2870] = {
    name ="MSG_ZONESTATUSREPLY",
  },
  [0x3970] = {
    name ="MSG_ZONESTATUSREPLY2",
  },
  [0x2770] = {
    name ="MSG_ZONESTATUSREQUEST",
  },
  [0x3870] = {
    name ="MSG_ZONESTATUSREQUEST2",
  },
  [0x0480] = {
    name ="MSG_ZONE_ADDRESS",
  },
  [0xa840] = {
    name ="MSG_ZONE_ALL",
  },
  [0xb040] = {
    name ="MSG_ZONE_HANDOVER_PC",
  },
  [0xe241] = {
    name ="MSG_ZONE_SKY",
  },
  [0x0580] = {
    name ="MSG_ZONE_UNAVAILABLE",
  },
  [0x1820] = {
    name ="MSG_ZREQ_LOOTERS",
  },
  [0x2720] = {
    name ="MSG_ZSERVER_ADDGROUPMEM",
  },
  [0x1a20] = {
    name ="MSG_ZSERVER_APP_ALIVE",
  },
  [0x1e20] = {
    name ="MSG_ZSERVER_CRASH",
  },
  [0x3c20] = {
    name ="MSG_ZSERVER_CREATEGRP",
  },
  [0x2820] = {
    name ="MSG_ZSERVER_DELGROUPMEM",
  },
  [0x2920] = {
    name ="MSG_ZSERVER_DISBAND",
  },
  [0x1120] = {
    name ="MSG_ZSERVER_READY",
  },
  [0xa340] = {
    name ="MSG_ZSERVER_STATUS",
  },
}