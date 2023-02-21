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

eq_protocol.fields = {
  flags, flag_unknown_bit_0, flag_has_ack_request, flag_is_closing, flag_is_fragment, flag_has_ack_counter,
  flag_is_first_packet, flag_is_closing_2, flag_is_sequence_end, flag_is_keep_alive_ack, flag_unknown_bit_9,
  flag_has_ack_response, flag_unknown_bit_11, flag_unknown_bit_12, flag_unknown_bit_13, flag_unknown_bit_14, flag_unknown_bit_15,
  header_sequence_number, header_ack_response, header_ack_request, header_fragment_sequence, header_fragment_current,
  header_fragment_total, header_ack_counter_high, header_ack_counter_low,
  opcode, payload, crc
}

function eq_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
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
  if bytes_remaining > 0 and has_opcode then
    subtree:add(opcode, buffer(header_offset, 2))
    header_offset = header_offset + 2
    bytes_remaining = bytes_remaining - 2
  end

  if bytes_remaining > 0 then
    subtree:add(payload, buffer(header_offset, bytes_remaining))
  end

  subtree:add_le(crc, buffer(length - crc_length, crc_length))
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(5998, eq_protocol)
udp_port:add(9000, eq_protocol)
