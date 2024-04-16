using System.Text;
using IpkSniffer.Cli;
using PacketDotNet;

namespace IpkSniffer;

/// <summary>
/// Printing of Network Layer packet data
/// </summary>
static class L3
{
    public static FilterData PrintIPv4Packet(
        IPv4Packet packet,
        StringBuilder sb
    ) {
        sb.AppendLine($"      src IP: {packet.SourceAddress}");
        sb.AppendLine($"      dst IP: {packet.SourceAddress}");
        sb.AppendLine($"          L4: {packet.Protocol}");

        return packet.PayloadPacket switch
        {
            TcpPacket p => L4.PrintTcpPacket(p, sb),
            UdpPacket p => L4.PrintUdpPacket(p, sb),
            IcmpV4Packet p => L4.PrintIcmpV4Packet(p, sb),
            IcmpV6Packet p => L4.PrintIcmpV6Packet(p, sb),
            IgmpPacket p => L4.PrintIgmpPacket(p, sb),
            OspfPacket p => L4.PrintOspfPacket(p, sb),
            IPv4Packet p => PrintIPv4Packet(p, sb),
            IPv6Packet p => PrintIPv6Packet(p, sb),
            GrePacket p => L4.PrintGrePacket(p, sb),
            _ => new(Filter.None),
        };
    }

    public static FilterData PrintIPv6Packet(
        IPv6Packet packet,
        StringBuilder sb
    ) {
        sb.AppendLine($"      src IP: {packet.SourceAddress}");
        sb.AppendLine($"      dst IP: {packet.SourceAddress}");
        sb.AppendLine($"          L4: {packet.Protocol}");

        return packet.PayloadPacket switch
        {
            TcpPacket p => L4.PrintTcpPacket(p, sb),
            UdpPacket p => L4.PrintUdpPacket(p, sb),
            IcmpV4Packet p => L4.PrintIcmpV4Packet(p, sb),
            IcmpV6Packet p => L4.PrintIcmpV6Packet(p, sb),
            IgmpPacket p => L4.PrintIgmpPacket(p, sb),
            OspfPacket p => L4.PrintOspfPacket(p, sb),
            IPv4Packet p => PrintIPv4Packet(p, sb),
            IPv6Packet p => PrintIPv6Packet(p, sb),
            GrePacket p => L4.PrintGrePacket(p, sb),
            _ => new(Filter.None),
        };
    }

    public static FilterData PrintArpPacket(
        ArpPacket _packet,
        StringBuilder _sb
    ) => new(Filter.None);

    public static FilterData PrintLldpPacket(
        LldpPacket packet,
        StringBuilder sb
    ) => new(Filter.None);

    public static FilterData PrintPppoePacket(
        PppoePacket packet,
        StringBuilder sb
    ) => packet.PayloadPacket switch
    {
        PppPacket p => L2.PrintPppPacket(p, sb),
        _ => new(Filter.None),
    };

    public static FilterData PrintWakeOnLanPacket(
        WakeOnLanPacket _packet,
        StringBuilder _sb
    ) => new(Filter.None);

    public static FilterData PrintIeee8021QPacket(
        Ieee8021QPacket packet,
        StringBuilder sb
    ) {
        sb.AppendLine($"          L2: {packet.Type}");

        return packet.PayloadPacket switch
        {
            IPv4Packet p => PrintIPv4Packet(p, sb),
            IPv6Packet p => PrintIPv6Packet(p, sb),
            ArpPacket p => PrintArpPacket(p, sb),
            LldpPacket p => PrintLldpPacket(p, sb),
            PppoePacket p => PrintPppoePacket(p, sb),
            WakeOnLanPacket p => PrintWakeOnLanPacket(p, sb),
            Ieee8021QPacket p => PrintIeee8021QPacket(p, sb),
            _ => new(Filter.None),
        };
    }
}
