export PcapFileHeader, PcapRec, PcapOffline,
       pcap_get_record

reverse(b::UInt16) = (b << 8) | (b >> 8)
reverse(b::UInt32) = (b << 24) | ((b << 8) & 0x00FF0000) | ((b >> 8) & 0x0000FF00) | (b >> 24)

type PcapFileHeader
    magic_number::UInt32
    version_major::UInt16
    version_minor::UInt16
    thiszone::Int32
    sigfigs::UInt32
    snaplen::UInt32
    network::UInt32
    readfunc::Function

    PcapFileHeader() = new(0,0,0,0,0,0,0,(x->x))

    function PcapFileHeader(file)
        magic_number  = read(file, UInt32)
        readfunc = magic_number == 0xa1b2c3d4 ? (x -> x) : reverse
        version_major = readfunc(read(file, UInt16))
        version_minor = readfunc(read(file, UInt16))
        thiszone      = readfunc(read(file, UInt32))
        sigfigs       = readfunc(read(file, UInt32))
        snaplen       = readfunc(read(file, UInt32))
        network       = readfunc(read(file, UInt32))

        new(magic_number, version_major, version_minor,
            thiszone, sigfigs, snaplen, network, readfunc)
    end
end # type PcapFileHeader

type PcapRec
    ts_sec::UInt32
    ts_usec::UInt32
    incl_len::UInt32
    orig_len::UInt32
    payload::Array{UInt8}
    PcapRec() = new(0,0,0,0, Array(UInt8, 0))
    function PcapRec(s)
        readfunc = s.filehdr.readfunc
        ts_sec   = readfunc(read(s.file, UInt32))
        ts_usec  = readfunc(read(s.file, UInt32))
        incl_len = readfunc(read(s.file, UInt32))
        orig_len = readfunc(read(s.file, UInt32))
        payload  = readbytes(s.file, incl_len)
        new(ts_sec, ts_usec, incl_len, orig_len, payload)
    end
end # type PcapRec

type PcapOffline
    filename::AbstractString
    file::IO
    filehdr::PcapFileHeader
    record::PcapRec
    hdr_read::Bool

    function PcapOffline(fn::AbstractString)
        filename = fn
        file     = open(fn, "r+")
        filehdr  = PcapFileHeader()
        record   = PcapRec()
        hdr_read = false
        new(filename, file, filehdr, record, hdr_read)
    end # constructor

    function PcapOffline(fileio::IO)
        filename = "unknown"
        file     = fileio
        filehdr  = PcapFileHeader()
        record   = PcapRec()
        hdr_read = false
        new(filename, file, filehdr, record, hdr_read)
    end # constructor

end # type PcapOffline

#----------
# decode PCap file format header
#----------
function pcap_get_header(s::PcapOffline)
    s.filehdr  = PcapFileHeader(s.file)
    s.hdr_read = true
end # function pcap_get_header

#----------
# decode next record in PCap file
#----------
function pcap_get_record(s::PcapOffline)
    if (s.hdr_read != true)
        pcap_get_header(s)
    end

    if (!eof(s.file))
        rec = PcapRec(s)
        return rec
    end

    nothing
end # function pcap_get_record
