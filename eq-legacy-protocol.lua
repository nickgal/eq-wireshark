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

SHARED_FIELDS = {
  reassembled_label = {
    type = ProtoField.bytes,
    name = "reassembled",
    args = { "EQ Protocol Data (Reassembled)" },
  },
  fragment_label = {
    type = ProtoField.bytes,
    name = "fragment",
    args = { "EQ Protocol Data Fragment" },
  },
  flags_label = {
    type = function(name) return ProtoField.new("Flags", name, ftypes.UINT16, nil, base.HEX) end,
    name = "flags",
  },

  flag_unknown_bit_0 = {
    type = ProtoField.bool,
    name = "flags.unknown_bit_0",
    args = { "UnknownBit0", 16, nil, Flags.UnknownBit0 },
  },
  flag_has_ack_request = {
    type = ProtoField.bool,
    name = "flags.has_ack_request",
    args = { "HasAckRequest", 16, nil, Flags.HasAckRequest },
  },
  flag_is_closing = {
    type = ProtoField.bool,
    name = "flags.is_closing",
    args = { "IsClosing", 16, nil, Flags.IsClosing },
  },
  flag_is_fragment = {
    type = ProtoField.bool,
    name = "flags.is_fragment",
    args = { "IsFragment", 16, nil, Flags.IsFragment },
  },
  flag_has_ack_counter = {
    type = ProtoField.bool,
    name = "flags.has_ack_counter",
    args = { "HasAckCounter", 16, nil, Flags.HasAckCounter },
  },
  flag_is_first_packet = {
    type = ProtoField.bool,
    name = "flags.is_first_packet",
    args = { "IsFirstPacket", 16, nil, Flags.IsFirstPacket },
  },
  flag_is_closing_2 = {
    type = ProtoField.bool,
    name = "flags.is_closing_2",
    args = { "IsClosing2", 16, nil, Flags.IsClosing2 },
  },
  flag_is_sequence_end = {
    type = ProtoField.bool,
    name = "flags.is_sequence_end",
    args = { "IsSequenceEnd", 16, nil, Flags.IsSequenceEnd },
  },
  flag_is_keep_alive_ack = {
    type = ProtoField.bool,
    name = "flags.is_keep_alive_ack",
    args = { "IsKeepAliveAck", 16, nil, Flags.IsKeepAliveAck },
  },
  flag_unknown_bit_9 = {
    type = ProtoField.bool,
    name = "flags.unknown_bit_9",
    args = { "UnknownBit9", 16, nil, Flags.UnknownBit9 },
  },
  flag_has_ack_response = {
    type = ProtoField.bool,
    name = "flags.has_ack_response",
    args = { "HasAckResponse", 16, nil, Flags.HasAckResponse },
  },
  flag_unknown_bit_11 = {
    type = ProtoField.bool,
    name = "flags.unknown_bit_11",
    args = { "UnknownBit11", 16, nil, Flags.UnknownBit11 },
  },
  flag_unknown_bit_12 = {
    type = ProtoField.bool,
    name = "flags.unknown_bit_12",
    args = { "UnknownBit12", 16, nil, Flags.UnknownBit12 },
  },
  flag_unknown_bit_13 = {
    type = ProtoField.bool,
    name = "flags.unknown_bit_13",
    args = { "UnknownBit13", 16, nil, Flags.UnknownBit13 },
  },
  flag_unknown_bit_14 = {
    type = ProtoField.bool,
    name = "flags.unknown_bit_14",
    args = { "UnknownBit14", 16, nil, Flags.UnknownBit14 },
  },
  flag_unknown_bit_15 = {
    type = ProtoField.bool,
    name = "flags.unknown_bit_15",
    args = { "UnknownBit15", 16, nil, Flags.UnknownBit15 },
  },

  header_sequence_number = {
    type = ProtoField.uint16,
    name = "header.sequence_number",
    args = { "SequenceNumber", base.HEX },
  },
  header_ack_response = {
    type = ProtoField.uint16,
    name = "header.ack_response",
    args = { "AckResponse", base.HEX },
  },
  header_ack_request = {
    type = ProtoField.uint16,
    name = "header.ack_request",
    args = { "AckRequest", base.HEX },
  },
  header_fragment_sequence = {
    type = ProtoField.uint16,
    name = "header.fragment_sequence",
    args = { "FragmentSequence", base.HEX },
  },
  header_fragment_current = {
    type = ProtoField.uint16,
    name = "header.fragment_current",
    args = { "FragmentCurrent", base.HEX },
  },
  header_fragment_total = {
    type = ProtoField.uint16,
    name = "header.fragment_total",
    args = { "FragmentTotal", base.HEX },
  },
  header_ack_counter_high = {
    type = ProtoField.uint8,
    name = "header.ack_counter_high",
    args = { "AckCounterHigh", base.HEX },
  },
  header_ack_counter_low = {
    type = ProtoField.uint8,
    name = "header.ack_counter_low",
    args = { "AckCounterLow", base.HEX },
  },

  opcode = {
    type = ProtoField.uint16,
    name = "opcode",
    args = { "OpCode", base.HEX },
  },
  payload = {
    type = ProtoField.bytes,
    name = "payload",
    args = { "Payload" },
  },
  crc = {
    type = ProtoField.uint32,
    name = "crc",
    args = { "CRC32", base.HEX },
  },
}

function make_shared_fields(prefix)
  local result = {}

  for key, field_def in pairs(SHARED_FIELDS) do
    local name = prefix .. "." .. field_def.name
    local field = field_def.type(name, unpack(field_def.args or {}))
    result[key] = field
  end

  return result
end

function dissect_metadata(protocol, tree, buffer)
  local flags_length = 2
  local flags_buffer = buffer(0, flags_length)
  local flags_value = flags_buffer:le_uint()
  local flags = {
    unknown_bit_0     = bit.band(flags_value, Flags.UnknownBit0) ~= 0,
    has_ack_request   = bit.band(flags_value, Flags.HasAckRequest) ~= 0,
    is_closing        = bit.band(flags_value, Flags.IsClosing) ~= 0,
    is_fragment       = bit.band(flags_value, Flags.IsFragment) ~= 0,
    has_ack_counter   = bit.band(flags_value, Flags.HasAckCounter) ~= 0,
    is_first_packet   = bit.band(flags_value, Flags.IsFirstPacket) ~= 0,
    is_closing_2      = bit.band(flags_value, Flags.IsClosing2) ~= 0,
    is_sequence_end   = bit.band(flags_value, Flags.IsSequenceEnd) ~= 0,
    is_keep_alive_ack = bit.band(flags_value, Flags.IsKeepAliveAck) ~= 0,
    unknown_bit_9     = bit.band(flags_value, Flags.UnknownBit9) ~= 0,
    has_ack_response  = bit.band(flags_value, Flags.HasAckResponse) ~= 0,
    unknown_bit_11    = bit.band(flags_value, Flags.UnknownBit11) ~= 0,
    unknown_bit_12    = bit.band(flags_value, Flags.UnknownBit12) ~= 0,
    unknown_bit_13    = bit.band(flags_value, Flags.UnknownBit13) ~= 0,
    unknown_bit_14    = bit.band(flags_value, Flags.UnknownBit14) ~= 0,
    unknown_bit_15    = bit.band(flags_value, Flags.UnknownBit15) ~= 0,
  }
  local fragment = nil

  -- Space-saving shortcut
  local sf = protocol.shared_fields

  -- Flag dissector data
  local flag_tree = tree:add(sf.flags_label, flags_buffer)
  flag_tree:add_le(sf.flag_unknown_bit_0, flags_buffer)
  flag_tree:add_le(sf.flag_has_ack_request, flags_buffer)
  flag_tree:add_le(sf.flag_is_closing, flags_buffer)
  flag_tree:add_le(sf.flag_is_fragment, flags_buffer)
  flag_tree:add_le(sf.flag_has_ack_counter, flags_buffer)
  flag_tree:add_le(sf.flag_is_first_packet, flags_buffer)
  flag_tree:add_le(sf.flag_is_closing_2, flags_buffer)
  flag_tree:add_le(sf.flag_is_sequence_end, flags_buffer)
  flag_tree:add_le(sf.flag_is_keep_alive_ack, flags_buffer)
  flag_tree:add_le(sf.flag_unknown_bit_9, flags_buffer)
  flag_tree:add_le(sf.flag_has_ack_response, flags_buffer)
  flag_tree:add_le(sf.flag_unknown_bit_11, flags_buffer)
  flag_tree:add_le(sf.flag_unknown_bit_12, flags_buffer)
  flag_tree:add_le(sf.flag_unknown_bit_13, flags_buffer)
  flag_tree:add_le(sf.flag_unknown_bit_14, flags_buffer)
  flag_tree:add_le(sf.flag_unknown_bit_15, flags_buffer)

  local header_offset = flags_length
  local header_tree = tree:add(protocol.protocol, buffer(header_offset), "[Header]")

  header_tree:add(sf.header_sequence_number, buffer(header_offset, 2))
  header_offset = header_offset + 2

  if flags.has_ack_response then
    header_tree:add(sf.header_ack_response, buffer(header_offset, 2))
    header_offset = header_offset + 2
  end
  if flags.has_ack_request then
    header_tree:add(sf.header_ack_request, buffer(header_offset, 2))
    header_offset = header_offset + 2
  end
  local has_opcode = true
  if flags.is_fragment then
    local seq = buffer(header_offset, 2)
    header_tree:add(sf.header_fragment_sequence, seq)
    header_offset = header_offset + 2;

    local cur = buffer(header_offset, 2)
    header_tree:add(sf.header_fragment_current, cur)
    header_offset = header_offset + 2;

    -- The first fragment has an opcode
    has_opcode = cur:uint() == 0

    local total = buffer(header_offset, 2)
    header_tree:add(sf.header_fragment_total, total)
    header_offset = header_offset + 2;

    fragment = {
      sequence = seq:uint(),
      current  = cur:uint(),
      total    = total:uint(),
    }
  end
  if flags.has_ack_counter then
    header_tree:add(sf.header_ack_counter_high, buffer(header_offset, 1))
    header_offset = header_offset + 1;
  end
  if flags.has_ack_counter and flags.has_ack_request then
    header_tree:add(sf.header_ack_counter_low, buffer(header_offset, 1))
    header_offset = header_offset + 1;
  end

  -- Finalize header length
  header_tree:set_len(header_offset - flags_length)

  local crc_length = 4
  local bytes_remaining = buffer:len() - header_offset - crc_length

  local crc_buffer = buffer(buffer:len() - crc_length, crc_length)

  local opcode_data = nil
  local body_buffer_with_opcode = buffer(header_offset, bytes_remaining)
  if bytes_remaining > 0 and has_opcode then
    local opcode_buffer = buffer(header_offset, 2)
    local opcode_value = opcode_buffer:uint()
    opcode_data = protocol.opcodes[opcode_value] or {name =  string.format("0x%X", opcode_value)}

    tree:add(sf.opcode, opcode_buffer(), opcode_buffer():uint(), nil, opcode_data.name)

    header_offset = header_offset + 2
    bytes_remaining = bytes_remaining - 2
  end

  local body_buffer = buffer(header_offset, bytes_remaining)

  return {
    flags                   = flags,
    fragment                = fragment,
    opcode                  = opcode_data,
    body_buffer             = body_buffer,
    body_buffer_with_opcode = body_buffer_with_opcode,
    crc_buffer              = crc_buffer,
  }
end

function reassemble_fragment(protocol, pinfo, fragment, fragment_opcode, buffer)
  -- Fragment sequence numbers are tracked for each side of a
  -- connection. This isn't an amazing way to express that (it'll probably
  -- fail badly on long captures), but it works for small ones.
  local fragment_key = (
    tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port) .. "-" ..
    tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port) ..
    "@" .. tostring(fragment.sequence))

  if protocol.MsgFragments[fragment_key] == nil then
    protocol.MsgFragments[fragment_key] = {}
  end

  local packet = protocol.MsgFragments[fragment_key]
  if packet.complete then
    -- Already built the whole packet, return it
    return packet
  end

  -- Packet isn't complete yet, safe to modify
  if fragment_opcode then
    -- Track the opcode across all fragments for readability
    packet.opcode = fragment_opcode
  end

  -- Add all packet fragments with array-like indexes
  -- Converting to 1-index so #packet reports length accurately
  packet[fragment.current + 1] = buffer:bytes()

  if #packet < fragment.total then
    -- More fragments to collect, return incomplete
    return {
      complete = false,
      opcode = packet.opcode,
      buffer = nil,
    }
  end

  -- We've collected all the fragments; packet is ready to reassemble
  local reassembledPacket = ByteArray.new()
  for _, value in ipairs(packet) do
    reassembledPacket = reassembledPacket .. value
  end

  -- Mark the packet as handled and save the buffer.
  -- Packets are visited multiple times, so we can't discard
  -- the data after this - but replacing the packet with a
  -- combined result means the individual fragments can be
  -- garbage collected.
  local result = {
    opcode = packet.opcode,
    buffer = reassembledPacket,
    complete = true,
  }
  protocol.MsgFragments[fragment_key] = result

  return result
end

function shared_dissector(protocol, buffer, pinfo, tree)
  local length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = protocol.protocol.name

  local subtree = tree:add(protocol.protocol, buffer(), "EQ Protocol Data")
  local meta = dissect_metadata(protocol, subtree, buffer)

  -- Space-saving shortcut
  local sf = protocol.shared_fields

  -- Track body subtree and buffer separately, so reassembled packets can be shown
  local body_subtree = subtree
  local body_buffer = meta.body_buffer
  if meta.fragment then
    local reassembled = reassemble_fragment(
      protocol, pinfo, meta.fragment, meta.opcode, meta.body_buffer_with_opcode)

    -- Track opcodes across fragmented packets
    if reassembled and reassembled.opcode then
      meta.opcode = reassembled.opcode
    end

    if reassembled and reassembled.complete then
      -- Fully reassembled packet; replace the body buffer/subtree based on the reassembled buffer
      body_buffer = reassembled.buffer:tvb("reassembled")
      body_subtree = tree:add(sf.reassembled_label, body_buffer())

      -- Pull opcode off the front of the buffer first
      local opcode_buffer = body_buffer(0, 2)
      body_buffer = body_buffer(2)
      body_subtree:add(sf.opcode, opcode_buffer, opcode_buffer:uint(), nil, reassembled.opcode.name)
    else
      -- Not a full packet, do not dissect the whole body
      meta.incomplete = true
    end
  end

  if meta.opcode then
    pinfo.cols.info = "[" .. meta.opcode.name .. "] " .. tostring(pinfo.cols['info'])
  end

  -- Mark the fragment bytes
  if meta.fragment then
    subtree:add(sf.fragment_label, meta.body_buffer())
  end

  if body_buffer:len() > 0 and not meta.incomplete then
    -- Add the payload to the body subtree, which can be different from
    -- subtree if this is a reassembled buffer
    add_payload(protocol, body_subtree, body_buffer, meta.opcode)
  end

  local crc_length = 4
  subtree:add_le(sf.crc, buffer(length - crc_length, crc_length))
end

function add_payload(protocol, subtree, buffer, opcode_data)
  if opcode_data == nil or opcode_data.dissect == nil then
    subtree:add(protocol.shared_fields.payload, buffer())
  else
    local payload_subtree = subtree:add(protocol.protocol, buffer, opcode_data.name)
    opcode_data:dissect(payload_subtree, buffer)
  end
end

local function add_string(tree, field, buffer)
  local s = buffer:string()
  local len = #s
  tree:add(field, buffer(0, len), s)

  -- Returns the length in case the next string is offset by it
  return len
end
local function dissect_string(field_name)
  return function(self, tree, buffer)
    add_string(tree, self.f[field_name], buffer)
  end
end

GAME_OPCODES = {
  -- Opcodes with dissect handlers
  [0x0180] = {
    name ="MSG_SELECT_CHARACTER",
    f = {
      name = ProtoField.string("everquest.select_character.name", "Character Name"),
    },
    dissect = dissect_string("name"),
  },
  [0x0710] = {
    name ="MSG_ACCESS_GRANTED",
    f = {
      response = ProtoField.bool("everquest.access_granted.response", "Response"),
      name = ProtoField.string("everquest.access_granted.name", "Name"),
    },
    dissect = function(self, tree, buffer)
      tree:add(self.f.response, buffer(0, 1))
      add_string(tree, self.f.name, buffer(1, 64))
    end
  },
  [0x4740] = {
    name ="MSG_SEND_CHARACTERS",
    -- Ew: The fields of the character list are a repeated strut-of-arrays, so we're generating them
    -- instead of copying everything 10 times
    f = (function()
      local result = {}

      for i = 1, 10, 1 do
        local function s(prefix, suffix)
          if suffix == nil then
            return prefix .. tostring(i)
          else
            return prefix .. tostring(i) .. suffix
          end
        end

        local prefix = "everquest.send_characters.character"

        result[s("character")] = ProtoField.none(s(prefix), s("Character "))
        result[s("name")]      = ProtoField.string(s(prefix, ".name"), "Name")
        result[s("level")]     = ProtoField.uint8(s(prefix, ".level"), "Level")
        result[s("class")]     = ProtoField.uint8(s(prefix, ".class"), "Class")
        result[s("race")]      = ProtoField.uint16(s(prefix, ".race"), "Race")
        result[s("zone")]      = ProtoField.uint32(s(prefix, ".zone"), "Zone")
        result[s("gender")]    = ProtoField.uint8(s(prefix, ".gender"), "Gender")
        result[s("face")]      = ProtoField.uint8(s(prefix, ".face"), "Zone")

        result[s("equip")]     = ProtoField.none(s(prefix, ".equip"), "Equipment Textures") -- 9x uint32
        result[s("head")]      = ProtoField.uint32(s(prefix, ".equip.head"), "Head")
        result[s("chest")]     = ProtoField.uint32(s(prefix, ".equip.chest"), "Chest")
        result[s("arms")]      = ProtoField.uint32(s(prefix, ".equip.arms"), "Arms")
        result[s("wrist")]     = ProtoField.uint32(s(prefix, ".equip.wrist"), "Wrists")
        result[s("hands")]     = ProtoField.uint32(s(prefix, ".equip.hands"), "Hands")
        result[s("legs")]      = ProtoField.uint32(s(prefix, ".equip.legs"), "Legs")
        result[s("feet")]      = ProtoField.uint32(s(prefix, ".equip.feet"), "Feet")
        result[s("primary_e")]   = ProtoField.uint32(s(prefix, ".equip.primary"), "Main Hand")
        result[s("secondary_e")] = ProtoField.uint32(s(prefix, ".equip.secondary"), "Off Hand")

        result[s("colors")]      = ProtoField.none(s(prefix, ".cs_colors"), "Character Equipment Colors (RR GG BB 00)")
        result[s("head_c")]      = ProtoField.uint32(s(prefix, ".cs_colors.head"), "Head")
        result[s("chest_c")]     = ProtoField.uint32(s(prefix, ".cs_colors.chest"), "Chest")
        result[s("arms_c")]      = ProtoField.uint32(s(prefix, ".cs_colors.arms"), "Arms")
        result[s("wrist_c")]     = ProtoField.uint32(s(prefix, ".cs_colors.wrist"), "Wrists")
        result[s("hands_c")]     = ProtoField.uint32(s(prefix, ".cs_colors.hands"), "Hands")
        result[s("legs_c")]      = ProtoField.uint32(s(prefix, ".cs_colors.legs"), "Legs")
        result[s("feet_c")]      = ProtoField.uint32(s(prefix, ".cs_colors.feet"), "Feet")
        result[s("primary_c")]   = ProtoField.uint32(s(prefix, ".cs_colors.primary"), "Main Hand")
        result[s("secondary_c")] = ProtoField.uint32(s(prefix, ".cs_colors.secondary"), "Off Hand")

        result[s("deity")]      = ProtoField.uint16(s(prefix, ".deity"), "Deity")
        result[s("primary")]    = ProtoField.uint32(s(prefix, ".primary"), "Primary IDFile Number")
        result[s("secondary")]  = ProtoField.uint32(s(prefix, ".secondary"), "Secondary IDFile Number")
        result[s("haircolor")]  = ProtoField.uint8(s(prefix, ".haircolor"), "Hair Color")
        result[s("beardcolor")] = ProtoField.uint8(s(prefix, ".beardcolor"), "Beard Color")
        result[s("eyecolor1")]  = ProtoField.uint8(s(prefix, ".eyecolor1"), "Eye Color 2")
        result[s("eyecolor2")]  = ProtoField.uint8(s(prefix, ".eyecolor2"), "Eye Color 1")
        result[s("hairstyle")]  = ProtoField.uint8(s(prefix, ".hairstyle"), "Hairstyle")
        result[s("beard")]      = ProtoField.uint8(s(prefix, ".beard"), "Beard")
      end

      return result
      end)(),
    dissect = function(self, tree, buffer)
      for i = 1, 10, 1 do
        -- buffer isn't true, but the character is spread across the whole message
        local char = tree:add(self.f["character" .. i], buffer)
        local idx = i - 1

        add_string(char, self.f["name" .. i], buffer(idx * 64))
        char:add(self.f["level" .. i], buffer(640 + idx, 1))
        char:add(self.f["class" .. i], buffer(650 + idx, 1))
        char:add(self.f["race" .. i], buffer(660 + idx, 1))
        char:add_le(self.f["zone" .. i], buffer(680 + idx, 4))
        char:add(self.f["gender" .. i], buffer(720 + idx, 1))
        char:add(self.f["face" .. i], buffer(730 + idx, 1))

        local equip = char:add(self.f["equip" .. i], buffer(740 + idx, 36))
        equip:add_le(self.f["head" .. i],      buffer(740 + idx, 4))
        equip:add_le(self.f["chest" .. i],     buffer(744 + idx, 4))
        equip:add_le(self.f["arms" .. i],      buffer(748 + idx, 4))
        equip:add_le(self.f["wrist" .. i],     buffer(752 + idx, 4))
        equip:add_le(self.f["hands" .. i],     buffer(756 + idx, 4))
        equip:add_le(self.f["legs" .. i],      buffer(760 + idx, 4))
        equip:add_le(self.f["feet" .. i],      buffer(764 + idx, 4))
        equip:add_le(self.f["primary_e" .. i],   buffer(768 + idx, 4))
        equip:add_le(self.f["secondary_e" .. i], buffer(772 + idx, 4))

        local color = char:add(self.f["colors" .. i], buffer(1100 + idx, 36))
        color:add_le(self.f["head_c" .. i],      buffer(1100 + idx, 4))
        color:add_le(self.f["chest_c" .. i],     buffer(1104 + idx, 4))
        color:add_le(self.f["arms_c" .. i],      buffer(1108 + idx, 4))
        color:add_le(self.f["wrist_c" .. i],     buffer(1112 + idx, 4))
        color:add_le(self.f["hands_c" .. i],     buffer(1116 + idx, 4))
        color:add_le(self.f["legs_c" .. i],      buffer(1120 + idx, 4))
        color:add_le(self.f["feet_c" .. i],      buffer(1124 + idx, 4))
        color:add_le(self.f["primary_c" .. i],   buffer(1128 + idx, 4))
        color:add_le(self.f["secondary_c" .. i], buffer(1132 + idx, 4))

        char:add_le(self.f["deity" .. i], buffer(1460 + idx, 2))
        char:add_le(self.f["primary" .. i], buffer(1480 + idx, 4))
        char:add_le(self.f["secondary" .. i], buffer(1520 + idx, 4))
        char:add(self.f["haircolor" .. i], buffer(1560 + idx, 1))
        char:add(self.f["beardcolor" .. i], buffer(1570 + idx, 1))
        char:add(self.f["eyecolor1" .. i], buffer(1580 + idx, 1))
        char:add(self.f["eyecolor2" .. i], buffer(1590 + idx, 1))
        char:add(self.f["hairstyle" .. i], buffer(1600 + idx, 1))
        char:add(self.f["beard" .. i], buffer(1610 + idx, 1))
      end
    end
  },
  [0x5818] = {
    name ="MSG_LOGIN",
    f = {
      accountname = ProtoField.string("everquest.login.accountname", "Account Name"),
      password = ProtoField.string("everquest.login.password", "Password"),
      unknown1 = ProtoField.bytes("everquest.login.unknown1", "Unknown"),
      zoning = ProtoField.bool("everquest.login.zoning", "Zoning"),
      unknown2 = ProtoField.bytes("everquest.login.unknown2", "Unknown"),
    },
    dissect = function(self, tree, buffer)
      local password_offset = 1 + add_string(tree, self.f.accountname, buffer(0, 127))
      add_string(tree, self.f.password, buffer(password_offset, 15))

      tree:add(self.f.unknown1, buffer(151, 41))
      tree:add(self.f.zoning, buffer(192, 1))
      tree:add(self.f.unknown2, buffer(193, 3))
    end
  },
  [0xc341] = {
    name ="MSG_RPSERVER",
    f = {
      fv = ProtoField.bool("everquest.rpserver.fv", "FV rules"),
      pvp = ProtoField.bool("everquest.rpserver.pvp", "PVP"),
      auto_identify = ProtoField.bool("everquest.rpserver.auto_identify", "Auto Identify"),
      namegen = ProtoField.bool("everquest.rpserver.namegen", "Name Gen"),
      gibberish = ProtoField.bool("everquest.rpserver.gibberish", "Gibberish"),
      testserver = ProtoField.bool("everquest.rpserver.testserver", "Test Server"),
      locale = ProtoField.uint32("everquest.rpserver.locale", "Locale"),
      profanity_filter = ProtoField.bool("everquest.rpserver.profanity_filter", "Profanity Filter"),
      worldshortname = ProtoField.string("everquest.rpserver.worldshortname", "World Shortname"),
      loggingserverpassword = ProtoField.string("everquest.rpserver.loggingserver_password", "Logging Server Password"),
      loggingserveraddress = ProtoField.string("everquest.rpserver.loggingserver_address", "Logging Server Address"),
      loggingserverport = ProtoField.uint32("everquest.rpserver.loggingserver_port", "Logging Server Port"),
      localizedemailaddress = ProtoField.string("everquest.rpserver.localized_email", "Localized Email Address"),
      unknown1 = ProtoField.bytes("everquest.rpserver.unknown1", "Unknown"),
      unknown2 = ProtoField.bytes("everquest.rpserver.unknown2", "Unknown"),
    },
    dissect = function(self, tree, buffer)
      tree:add(self.f.fv, buffer(0, 4))
      tree:add(self.f.pvp, buffer(4, 4))
      tree:add(self.f.auto_identify, buffer(8, 4))
      tree:add(self.f.namegen, buffer(12, 4))
      tree:add(self.f.gibberish, buffer(16, 4))
      tree:add(self.f.testserver, buffer(20, 4))
      tree:add_le(self.f.locale, buffer(24, 4))
      tree:add(self.f.profanity_filter, buffer(28, 4))
      add_string(tree, self.f.worldshortname, buffer(32, 32))
      add_string(tree, self.f.loggingserverpassword, buffer(64, 32))
      tree:add(self.f.unknown1, buffer(96, 16))
      add_string(tree, self.f.loggingserveraddress, buffer(112, 16))
      tree:add(self.f.unknown2, buffer(126, 48))
      tree:add_le(self.f.loggingserverport, buffer(176, 4))
      add_string(tree, self.f.localizedemailaddress, buffer(180, 64))
    end,
  },
  [0xd841] = {
    name ="MSG_KUNARK",
    f = {
      expansions = ProtoField.uint32("everquest.expansions.expansions", "Expansions"),
    },
    dissect = function(self, tree, buffer)
      tree:add_le(self.f.expansions, buffer(0, 4))
    end,
  },
  [0xdd41] = {
    name ="MSG_MOTD",
    f = {
      message =  ProtoField.string("everquest.motd.message", "Message"),
    },
    dissect = dissect_string("message"),
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
  [0x0a20] = {
    name ="MSG_SENDCORPSE_EQ",
  },
  [0x9e40] = {
    name ="MSG_SENDPC_EQ",
  },
  [0x1520] = {
    name ="MSG_SENDPC_WEQ",
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
  [0xa940] = {
    name ="MSG_START_CASTING",
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

LOGIN_OPCODES = {
  [0x0100] = {
    name = "OP_LoginInfo/OP_LoginPC",
    f = {
      encrypted_data = ProtoField.bytes("everquest_login.login.encrypted_data", "Encrypted Data"),
      last_server_name = ProtoField.string("everquest_login.login.last_server_name", "Last Server Name"),
    },
    dissect = function(self, tree, buffer)
      tree:add(self.f.encrypted_data, buffer(0, 40))
      add_string(tree, self.f.last_server_name, buffer(40))
    end,
  },
  [0x0200] = {
    name = "OP_FatalError/OP_ClientError",
  },
  [0x0400] = {
    name = "OP_SessionId/OP_LoginAccepted",
    f = {
      session_id = ProtoField.bytes("everquest_login.session_id.session_id", "Session ID"),
      unused = ProtoField.string("everquest_login.session_id.unused", "Unused"),
      unknown = ProtoField.uint32("everquest_login.session_id.unknown", "Unknown"),
    },
    dissect = function(self, tree, buffer)
      tree:add(self.f.session_id, buffer(0, 10))
      tree:add(self.f.unused, buffer(10, 7))
      tree:add_le(self.f.unknown, buffer(17))
    end,
  },
  [0x0500] = {
    name = "OP_AllFinish",
  },
  [0x0600] = {
    name = "OP_Chat_ChannelList",
  },
  [0x0700] = {
    name = "OP_Chat_JoinChannel",
  },
  [0x0800] = {
    name = "OP_Chat_PartChannel",
  },
  [0x0900] = {
    name = "OP_Chat_ChannelMessage",
  },
  [0x0a00] = {
    name = "OP_Chat_Tell",
  },
  [0x0b00] = {
    name = "OP_Chat_SysMsg",
  },
  [0x0c00] = {
    name = "OP_Chat_CreateChannel",
  },
  [0x0d00] = {
    name = "OP_Chat_ChangeChannel",
  },
  [0x0e00] = {
    name = "OP_Chat_DeleteChannel",
  },
  [0x1000] = {
    name = "OP_Chat_UserList",
  },
  [0x1a00] = {
    name = "OP_Reg_GetPricing",
  },
  [0x1b00] = {
    name = "SISAMSG_REGISTER",
  },
  [0x1d00] = {
    name = "SISAMSG_REGISTER_OK",
  },
  [0x2400] = {
    name = "OP_Chat_ChannelWelcome",
  },
  [0x3000] = {
    name = "OP_Chat_PopupMakeWindow",
  },
  [0x3300] = {
    name = "OP_BillingInfoAccepted",
  },
  [0x3400] = {
    name = "OP_CheckGameCardValid",
  },
  [0x3600] = {
    name = "OP_GameCardTimeLeft",
  },
  [0x4100] = {
    name = "SISAMSG_REPORT_REGISTER",
  },
  [0x4200] = {
    name = "SISAMSG_LOGIN_EXPIRED",
  },
  [0x4300] = {
    name = "SISAMSG_LOGIN_CANCELED",
  },
  [0x4500] = {
    name = "OP_ChangePassword",
  },
  [0x4600] = {
    name = "SISAMSG_LIST_EQSERVERS",
    f = {
      numservers = ProtoField.uint16("everquest_login.list_servers.numservers", "Number of Servers"),
      padding = ProtoField.uint16("everquest_login.list_servers.padding", "Padding"),
      show_user_count = ProtoField.uint16("everquest_login.list_servers.show_user_count", "Show User Count"),
      -- middle goes here
      server = ProtoField.string("everquest_login.list_servers.server0", "Name"),
      server_name = ProtoField.string("everquest_login.list_servers.server0.name", "Name"),
      server_address = ProtoField.string("everquest_login.list_servers.server0.address", "IP"),
      server_flag_greenname = ProtoField.uint32("everquest_login.list_servers.server0.greenname", "Green Name"),
      server_flags = ProtoField.uint32("everquest_login.list_servers.server0.flags", "Flags (0x8 means hidden)"),
      server_world_id = ProtoField.int32("everquest_login.list_servers.server0.world_id", "World ID"),
      server_user_count = ProtoField.uint32("everquest_login.list_servers.server0.user_count", "User Count"),
      -- end
      admin = ProtoField.uint16("everquest_login.list_servers.admin", "Admin"),
      unused = ProtoField.bytes("everquest_login.list_servers.unused", "Unused"),
      kunark = ProtoField.uint8("everquest_login.list_servers.kunark", "Kunark"),
      velious = ProtoField.uint8("everquest_login.list_servers.velious", "Velious"),
      unsed2 = ProtoField.bytes("everquest_login.list_servers.unused2", "Unused"),
    },
    --dissect = function(self, tree, buffer)
    --  tree:add(self.f.color, buffer(0, 4))
    --  add_string(tree, self.f.message, buffer(4))
    --end,
  },
  [0x4700] = {
    name = "OP_SessionKey/OP_PlayEverquestRequest",
  },
  [0x4800] = {
    name = "OP_RequestServerStatus/OP_LoginUnknown1",
  },
  [0x4900] = {
    name = "OP_ServerName",
  },
  [0x4a00] = {
    name = "OP_SendServerStatus/OP_LoginUnknown2",
  },
  [0x5100] = {
    name = "SISAMSG_OPTION_LOGIN",
  },
  [0x5200] = {
    name = "SISAMSG_BANNER",
    f = {
      -- Maybe color?
      unknown = ProtoField.bytes("everquest_login.banner.unknown", "Unknown"),
      message = ProtoField.string("everquest_login.banner.message", "Message"),
    },
    dissect = function(self, tree, buffer)
      tree:add(self.f.color, buffer(0, 4))
      add_string(tree, self.f.message, buffer(4))
    end,
  },
  [0x5500] = {
    name = "OP_Chat_GuildsList",
  },
  [0x5700] = {
    name = "OP_Chat_GuildEdit",
  },
  [0x5900] = {
    name = "OP_Version/OP_SessionReady",
    f = {
      message = ProtoField.string("everquest_login.session_ready.message", "Message"),
    },
    dissect = dissect_string("message"),
  },
  [0x7a00] = {
    name = "OP_RenewAccountBillingInfo",
  },
  [0x7c00] = {
    name = "SISAMSG_POLL",
  },
  [0x7f00] = {
    name = "SISAMSG_LOGIN_OEM",
  },
  [0x8800] = {
    name = "SISAMSG_REQUEST_PREMIUM_INFO",
  },
  [0x8e00] = {
    name = "OP_LoginOSX",
  },
  [0x9100] = {
    name = "TOKEN_PREORDER_LOY_BLURB",
  },
  [0x9200] = {
    name = "TOKEN_ORDER_LOY_BLURB",
  },
  [0x9300] = {
    name = "loy_order_success",
  },
}


function protocol_with_fields(protocol, opcode_table)
  local wrapped_protocol = {
    opcodes = opcode_table,
    protocol = protocol,
  }

  protocol.init = function()
    -- Initialize global fragment table
    wrapped_protocol.MsgFragments = {}
  end
  protocol.dissector = function(buffer, pinfo, tree)
    shared_dissector(wrapped_protocol, buffer, pinfo, tree)
  end

  -- copy fields
  local field_list = {}
  local shared_fields = {}
  for key, field in pairs(make_shared_fields(protocol.name)) do
    table.insert(field_list, field)
    shared_fields[key] = field
  end

  for _, opcode in pairs(opcode_table) do
    for _, field in pairs(opcode.f or {}) do
      table.insert(field_list, field)
    end
  end

  protocol.fields = field_list
  wrapped_protocol.shared_fields = shared_fields

  -- Wrap the protocol in a table with a few extra attributes
  return protocol
end

eq_protocol = protocol_with_fields(
  Proto("everquest",  "EQ Legacy Protocol"),
   GAME_OPCODES)

eq_login_protocol = protocol_with_fields(
  Proto("everquest_login",  "EQ Legacy Login Protocol"),
  LOGIN_OPCODES)

local udp_port = DissectorTable.get("udp.port")
udp_port:add(5998, eq_protocol)
udp_port:add(9000, eq_protocol)

udp_port:add(6000, eq_login_protocol)
