# TODO: Write documentation for `Hep`
module HEP
  VERSION = "0.1.0"
end

module HEP::Protocol
  def self.parse(bytes)
    packet = Packet.new(bytes)
    packet.parse
    packet
  end
end

class HEP::Protocol::Chunk::IPV4SourceAddress
  def initialize(chunk : Bytes)
    @chunk = chunk
  end

  def self.build(packet)
    new(packet.chunk(0x0003))
  end

  def to_s
    @chunk.map { |byte| byte.to_s(10) }.join('.')
  end
end

class HEP::Protocol::Packet
  def initialize(bytes : Bytes)
    @bytes = bytes
    @chunk_of = Hash(UInt32, Bytes).new
  end

  def parse
    io = IO::Memory.new(@bytes)
    header = io.read_bytes(UInt32, IO::ByteFormat::BigEndian)
    length = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

    while io.pos < length
      chunk_vendor = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      chunk_type = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      chunk_length = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      chunk_data = Bytes.new(chunk_length - 6)
      io.read_fully(chunk_data)

      chunk_id = (chunk_vendor.to_u32 << 16) | chunk_type.to_u32
      @chunk_of[chunk_id] = chunk_data
    end
  end

  def chunk(id)
    @chunk_of[id]
  end
end

class HEP::Protocol::Chunk::IPV4DestinationAddress
  def initialize(chunk : Bytes)
    @chunk = chunk
  end

  def self.build(packet)
    new(packet.chunk(0x0004))
  end

  def to_s
    @chunk.map { |byte| byte.to_s(10) }.join('.')
  end
end

class HEP::Protocol::Chunk::SourcePort
  def initialize(chunk : Bytes)
    @chunk = chunk
  end

  def self.build(packet)
    new(packet.chunk(0x0007))
  end

  def to_s
    io = IO::Memory.new(@chunk)
    port = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    port.to_s
  end
end

class HEP::Protocol::Chunk::DestinationPort
  def initialize(chunk : Bytes)
    @chunk = chunk
  end

  def self.build(packet)
    new(packet.chunk(0x0008))
  end

  def to_s
    io = IO::Memory.new(@chunk)
    port = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    port.to_s
  end
end

class HEP::Protocol::Chunk::SecondsTimestamp
  def initialize(chunk : Bytes)
    @chunk = chunk
  end

  def self.build(packet)
    new(packet.chunk(0x0009))
  end

  def to_s
    io = IO::Memory.new(@chunk)
    timestamp = io.read_bytes(UInt32, IO::ByteFormat::BigEndian)
    timestamp.to_s
  end
end

class HEP::Protocol::Chunk::MicrosecondsTimestampOffset
  def initialize(chunk : Bytes)
    @chunk = chunk
  end

  def self.build(packet)
    new(packet.chunk(0x000a))
  end

  def to_s
    io = IO::Memory.new(@chunk)
    microseconds = io.read_bytes(UInt32, IO::ByteFormat::BigEndian)
    microseconds.to_s
  end
end

class HEP::Protocol::Chunk::Protocol
  def initialize(chunk : Bytes)
    @chunk = chunk
  end

  def self.build(packet)
    new(packet.chunk(0x000b))
  end

  def to_s
    @chunk[0].to_s(16).rjust(2, '0')
  end
end

class HEP::Protocol::Chunk::CaptureID
  def initialize(chunk : Bytes)
    @chunk = chunk
  end

  def self.build(packet)
    new(packet.chunk(0x000c))
  end

  def to_s
    io = IO::Memory.new(@chunk)
    capture_id = io.read_bytes(UInt32, IO::ByteFormat::BigEndian)
    capture_id.to_s
  end
end

class HEP::Protocol::Chunk::Payload
  def initialize(chunk : Bytes)
    @chunk = chunk
  end

  def self.build(packet)
    new(packet.chunk(0x000f))
  end

  def to_s
    String.new(@chunk)
  end
end
