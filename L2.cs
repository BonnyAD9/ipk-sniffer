using System.Net.NetworkInformation;
using System.Text;
using IpkSniffer.Cli;
using PacketDotNet;
using PacketDotNet.Ieee80211;
using PacketDotNet.Utils;

namespace IpkSniffer;

/// <summary>
/// Printing of Link Layer packet data
/// </summary>
static class L2
{
    public static FilterData PrintEthernetPacket(
        EthernetPacket packet,
        StringBuilder sb
    ) {
        // Using the `HexPrinter.PrintMACAddress` so that it is printed in the
        // format with `:`
        sb.AppendLine(
            "     src MAC: "
                + HexPrinter.PrintMACAddress(packet.SourceHardwareAddress)
        );
        sb.AppendLine(
            "     dst MAC: "
                + HexPrinter.PrintMACAddress(packet.DestinationHardwareAddress)
        );
        sb.AppendLine($"          L3: {packet.Type}");

        return packet.PayloadPacket switch
        {
            IPv4Packet p => L3.PrintIPv4Packet(p, sb),
            IPv6Packet p => L3.PrintIPv6Packet(p, sb),
            ArpPacket p => L3.PrintArpPacket(p, sb),
            LldpPacket p => L3.PrintLldpPacket(p, sb),
            PppoePacket p => L3.PrintPppoePacket(p, sb),
            WakeOnLanPacket p => L3.PrintWakeOnLanPacket(p, sb),
            Ieee8021QPacket p => L3.PrintIeee8021QPacket(p, sb),
            _ => new(Filter.None),
        };
    }

    public static FilterData PrintLinuxSllPacket(
        LinuxSllPacket packet,
        StringBuilder sb
    ) {
        if (packet.LinkLayerAddressType == 1) {
            sb.AppendLine($"          L3: {packet.EthernetProtocolType}");
            var adr = new PhysicalAddress(packet.LinkLayerAddress[..6]);
            sb.AppendLine($"     src MAC: {HexPrinter.PrintMACAddress(adr)}");
        }

        return packet.PayloadPacket switch
        {
            IPv4Packet p => L3.PrintIPv4Packet(p, sb),
            IPv6Packet p => L3.PrintIPv6Packet(p, sb),
            ArpPacket p => L3.PrintArpPacket(p, sb),
            LldpPacket p => L3.PrintLldpPacket(p, sb),
            PppoePacket p => L3.PrintPppoePacket(p, sb),
            WakeOnLanPacket p => L3.PrintWakeOnLanPacket(p, sb),
            Ieee8021QPacket p => L3.PrintIeee8021QPacket(p, sb),
            _ => new(Filter.None),
        };
    }

    public static FilterData PrintNullPacket(NullPacket packet, StringBuilder sb)
    {
        sb.AppendLine($"          L3: {packet.Protocol}");

        return packet.PayloadPacket switch
        {
            IPv4Packet p => L3.PrintIPv4Packet(p, sb),
            IPv6Packet p => L3.PrintIPv6Packet(p, sb),
            _ => new(Filter.None),
        };
    }

    public static FilterData PrintPppPacket(PppPacket packet, StringBuilder sb)
    {
        sb.AppendLine($"          L3: {packet.Protocol}");

        return packet.PayloadPacket switch
        {
            IPv4Packet p => L3.PrintIPv4Packet(p, sb),
            IPv6Packet p => L3.PrintIPv6Packet(p, sb),
            _ => new(Filter.None),
        };
    }

    public static FilterData PrintMacFrame(MacFrame _packet, StringBuilder _sb)
        => new(Filter.None);

    public static FilterData PrintRadioPacket(
        RadioPacket _packet,
        StringBuilder _sb
    ) => new(Filter.None);

    public static FilterData PrintPpiPacket(
        PpiPacket _packet,
        StringBuilder _sb
    ) => new(Filter.None);

    public static FilterData PrintRawIPPacket(
        RawIPPacket packet,
        StringBuilder sb
    ) {
        sb.AppendLine($"          L3: {packet.Protocol}");

        return packet.PayloadPacket switch
        {
            IPv4Packet p => L3.PrintIPv4Packet(p, sb),
            IPv6Packet p => L3.PrintIPv6Packet(p, sb),
            _ => new(Filter.None),
        };
    }
}
