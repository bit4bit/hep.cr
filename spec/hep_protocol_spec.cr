require "./spec_helper"

describe HEP::Protocol do
  it "parse" do
    # TAKEN FROM: https://github.com/sipcapture/hep-go/blob/master/hep_test.go
    udp_packet = Bytes[
      0x48, 0x45, 0x50, 0x33, # HepID
      0x00, 0x71, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x02,
      0x00, 0x00, 0x00, 0x02, 0x00, 0x07, 0x11,                                                                               # protocol ID = 17 (UDP)
      0x00, 0x00, 0x00, 0x03, 0x00, 0x0a, 0xd4, 0xca, 0x00, 0x01,                                                             # IPv4 source address = 212.202.0.1
      0x00, 0x00, 0x00, 0x04, 0x00, 0x0a, 0x52, 0x74, 0x00, 0xd3,                                                             # IPv4 destination address = 82.116.0.211
      0x00, 0x00, 0x00, 0x07, 0x00, 0x08, 0x2e, 0xea,                                                                         # source port = 12010
      0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x13, 0xc4,                                                                         # destination port = 5060
      0x00, 0x00, 0x00, 0x09, 0x00, 0x0a, 0x4e, 0x49, 0x82, 0xcb,                                                             # seconds timestamp 1313440459 = Mon Aug 15 22:34:19 2011
      0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x01, 0xd4, 0xc0,                                                             # micro-seconds timestamp offset 120000 = 0.12 seconds
      0x00, 0x00, 0x00, 0x0b, 0x00, 0x07, 0x01,                                                                               # 01 – SIP
      0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x00, 0x00, 0xE4,                                                             # capture ID (228)
      0x00, 0x00, 0x00, 0x0f, 0x00, 0x14, 0x49, 0x4e, 0x56, 0x49, 0x54, 0x45, 0x20, 0x73, 0x69, 0x70, 0x3a, 0x62, 0x6f, 0x62, # SIP payload "INVITE sip:bob" (shortened)
    ]

    packet = HEP::Protocol.parse(udp_packet)
    HEP::Protocol::Chunk::IPV4SourceAddress.build(packet).to_s.should eq("212.202.0.1")
    HEP::Protocol::Chunk::IPV4DestinationAddress.build(packet).to_s.should eq("82.116.0.211")
    HEP::Protocol::Chunk::SourcePort.build(packet).to_s.should eq("12010")
    HEP::Protocol::Chunk::DestinationPort.build(packet).to_s.should eq("5060")
    HEP::Protocol::Chunk::SecondsTimestamp.build(packet).to_s.should eq("1313440459")
    HEP::Protocol::Chunk::MicrosecondsTimestampOffset.build(packet).to_s.should eq("120000")
    HEP::Protocol::Chunk::Protocol.build(packet).to_s.should eq("01")
    HEP::Protocol::Chunk::CaptureID.build(packet).to_s.should eq("228")
    HEP::Protocol::Chunk::Payload.build(packet).to_s.should eq("INVITE sip:bob")
  end
end
