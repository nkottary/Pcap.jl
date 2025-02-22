using Pcap
using Base.Test

# write your own tests here
#@test 1 == 1

#println(pcap_lookupdev())
#pcap_findalldevs()

function test_eth_hdr(ethhdr::EthHdr)
    @test "74:de:2b:08:78:09" == ethhdr.src_mac
    @test "00:24:fe:b1:8f:dc" == ethhdr.dest_mac
    @test 2048 == ethhdr.ptype
end # function test_ip_hdr

function test_ip_hdr(iphdr::IpHdr)
    @test 4 == iphdr.version
    @test 20 == iphdr.length
    @test 0 == iphdr.services
    @test 63 == iphdr.totlen
    @test 20831 == iphdr.id
    @test 64    == iphdr.ttl
    @test 17    == iphdr.protocol
    @test "192.168.0.51" == iphdr.src_ip
    @test "192.168.0.1"  == iphdr.dest_ip
    @test 0x67ca         == iphdr.checksum
end # function test_ip_hdr

function test_udp_hdr(udphdr::UdpHdr)
    @test 34904  == udphdr.src_port
    @test 53     == udphdr.dest_port
    @test 43     == udphdr.length
    @test 0xa24a == udphdr.checksum
end # function test_udp_hdr

cap     = PcapOffline("data/dns-query-response.pcap")
rec     = pcap_get_record(cap)
layers  = decode_pkt(rec.payload)

test_eth_hdr(layers.datalink)
test_ip_hdr(layers.network)
test_udp_hdr(layers.protocol)
