using System.Text;
using IpkSniffer.Cli;
using PacketDotNet;

namespace IpkSniffer;

static class L4
{
    public static FilterData PrintTcpPacket(
        TcpPacket packet,
        StringBuilder sb
    ) {
        sb.AppendLine($"    src port: {packet.SourcePort}");
        sb.AppendLine($"    dst port: {packet.DestinationPort}");
        return new FilterData(
            Filter.Tcp,
            packet.SourcePort,
            packet.DestinationPort
        );
    }

    public static FilterData PrintUdpPacket(
        UdpPacket packet,
        StringBuilder sb
    ) {
        sb.AppendLine($"    src port: {packet.SourcePort}");
        sb.AppendLine($"    dst port: {packet.DestinationPort}");
        return new FilterData(
            Filter.Udp,
            packet.SourcePort,
            packet.DestinationPort
        );
    }

    public static FilterData PrintIcmpV4Packet(
        IcmpV4Packet packet,
        StringBuilder sb
    ) {
        sb.AppendLine($"        type: {packet.TypeCode}");
        return new(Filter.Icmp4);
    }

    public static FilterData PrintIcmpV6Packet(
        IcmpV6Packet packet,
        StringBuilder sb
    ) {
        sb.AppendLine($"        type: {packet.Type}");
        var filter = Filter.Icmp6;

        switch (packet.Type)
        {
            case IcmpV6Type.MulticastListenerQuery:
            case IcmpV6Type.MulticastListenerReport:
            case IcmpV6Type.MulticastListenerDone:
            case IcmpV6Type.Version2MulticastListenerReport:
                filter |= Filter.Mld;
                break;
            case IcmpV6Type.RouterSolicitation:
            case IcmpV6Type.RouterAdvertisement:
            case IcmpV6Type.NeighborSolicitation:
            case IcmpV6Type.NeighborAdvertisement:
            case IcmpV6Type.RedirectMessage:
                filter |= Filter.Ndp;
                break;
        }

        return new(filter);
    }

    public static FilterData PrintIgmpPacket(
        IgmpPacket _packet,
        StringBuilder _sb
    ) => new(Filter.Igmp);

    public static FilterData PrintOspfPacket(
        OspfPacket _packet,
        StringBuilder _sb
    ) => new(Filter.None);

    public static FilterData PrintGrePacket(
        GrePacket _packet,
        StringBuilder _sb
    ) => new(Filter.None);
}
