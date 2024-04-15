using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text;
using System.Xml;
using IpkSniffer.Cli;
using PacketDotNet;
using PacketDotNet.Ieee80211;
using PacketDotNet.Utils;
using SharpPcap;

namespace IpkSniffer;

static class Program
{
    public static void Main(string[] args)
    {
        try
        {
            Init();
            Environment.Exit(Start(Args.Parse(args)));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failure: {ex.Message}");
            Debug.WriteLine(ex);
            Environment.Exit(1);
        }
    }

    static void Init()
    {
        if (!Console.IsInputRedirected)
        {
            Console.TreatControlCAsInput = true;
        }
    }

    static int Start(Args args) => args.Action switch
    {
        Cli.Action.List => List(),
        Cli.Action.Sniff => Sniff(args),
        _ => throw new UnreachableException("Invalid action."),
    };

    static int List()
    {
        foreach (var dev in CaptureDeviceList.Instance)
            Console.WriteLine(dev.Name);
        return 0;
    }

    static nuint count = 0;
    static nuint maxCount = 1;
    static FilterData filter = new(Filter.None);

    static int Sniff(Args args)
    {
        var device = CaptureDeviceList
            .Instance
            .First(d => d.Name == args.Interface);

        maxCount = args.PacketCount;
        filter = new(args.Filter, args.AnyPort, args.SrcPort, args.DstPort);

        device.Open(read_timeout: 100);
        device.OnPacketArrival += CapturePacket;

        device.StartCapture();

        bool cont = true;
        while (true)
        {
            if (count >= maxCount)
                cont = false;

            while (Console.KeyAvailable)
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.C
                    && key.Modifiers.HasFlag(ConsoleModifiers.Control)
                ) {
                    cont = false;
                }
            }

            if (!cont)
                break;

            Thread.Sleep(10);
        }

        device.StopCapture();
        device.Close();

        return 0;
    }

    static void CapturePacket(object sender, PacketCapture packet)
    {
        if (count >= maxCount)
            return;

        StringBuilder sb = new();
        if (count == 0) {

            sb.AppendLine(
                "-------------------------------------------------------------"
                    + "--------------"
            );
        }
        var dateStr = XmlConvert.ToString(
            packet.Header.Timeval.Date,
            XmlDateTimeSerializationMode.Local
        );
        sb.AppendLine($"    packet #: {count + 1}/{maxCount}");
        sb.AppendLine($"   timestamp: {dateStr}");
        sb.AppendLine($"frame length: {packet.Data.Length} bytes");

        var type = PrintLinkLayer(packet.GetPacket(), sb);
        if (!filter.ShouldShow(type))
            return;

        count += 1;
        Console.WriteLine(sb);
        HexDump(packet.Data);
    }

    static void HexDump(ReadOnlySpan<byte> data)
    {
        Console.WriteLine(
            "        0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F  "
                + " 01234567 89ABCDEF"
        );

        void PrintHex(ReadOnlySpan<byte> data)
        {
            for (int i = 0; i < 16; ++i)
            {
                if (i == 8)
                    Console.Write(" ");

                if (i >= data.Length)
                {
                    Console.Write("   ");
                    continue;
                }

                Console.Write($"{data[i]:x2} ");
            }
        }

        void PrintAscii(ReadOnlySpan<byte> data)
        {
            for (int i = 0; i < 16; ++i)
            {
                if (i == 8)
                    Console.Write(" ");

                if (i >= data.Length)
                {
                    Console.Write(" ");
                    continue;
                }

                if (data[i] is < 32 or >= 127)
                    Console.Write(".");
                else
                    Console.Write((char)data[i]);
            }
        }

        var offset = 0;
        while (data.Length != 0) {
            Console.Write($"0x{offset:X4}: ");
            PrintHex(data);
            Console.Write(" ");
            PrintAscii(data);
            offset += 16;
            Console.WriteLine();
            if (data.Length < 16)
                break;
            data = data[16..];
        }
        Console.WriteLine(
            "-----------------------------------------------------------------"
                + "----------"
        );
    }

    static FilterData PrintLinkLayer(RawCapture packet, StringBuilder sb)
    {
        sb.AppendLine($"          L2: {packet.LinkLayerType}");

        return packet.GetPacket() switch
        {
            EthernetPacket p => PrintEthernetPacket(p, sb),
            LinuxSllPacket p => PrintLinuxSllPacket(p, sb),
            NullPacket p => PrintNullPacket(p, sb),
            PppPacket p => PrintPppPacket(p, sb),
            MacFrame p => PrintMacFrame(p, sb),
            RadioPacket p => PrintRadioPacket(p, sb),
            PpiPacket p => PrintPpiPacket(p, sb),
            RawIPPacket p => PrintRawIPPacket(p, sb),
            _ => new FilterData(Filter.None),
        };
    }

    // L2

    private static FilterData PrintEthernetPacket(
        EthernetPacket packet,
        StringBuilder sb
    ) {
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
            IPv4Packet p => PrintIPv4Packet(p, sb),
            IPv6Packet p => PrintIPv6Packet(p, sb),
            ArpPacket p => PrintArpPacket(p, sb),
            LldpPacket p => PrintLldpPacket(p, sb),
            PppoePacket p => PrintPppoePacket(p, sb),
            WakeOnLanPacket p => PrintWakeOnLanPacket(p, sb),
            Ieee8021QPacket p => PrintIeee8021QPacket(p, sb),
            _ => new FilterData(Filter.None),
        };
    }

    private static FilterData PrintLinuxSllPacket(
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
            IPv4Packet p => PrintIPv4Packet(p, sb),
            IPv6Packet p => PrintIPv6Packet(p, sb),
            ArpPacket p => PrintArpPacket(p, sb),
            LldpPacket p => PrintLldpPacket(p, sb),
            PppoePacket p => PrintPppoePacket(p, sb),
            WakeOnLanPacket p => PrintWakeOnLanPacket(p, sb),
            Ieee8021QPacket p => PrintIeee8021QPacket(p, sb),
            _ => new FilterData(Filter.None),
        };
    }

    private static FilterData PrintNullPacket(NullPacket packet, StringBuilder sb)
    {
        sb.AppendLine($"          L3: {packet.Protocol}");

        return packet.PayloadPacket switch
        {
            IPv4Packet p => PrintIPv4Packet(p, sb),
            IPv6Packet p => PrintIPv6Packet(p, sb),
            _ => new FilterData(Filter.None),
        };
    }

    private static FilterData PrintPppPacket(PppPacket packet, StringBuilder sb)
    {
        sb.AppendLine($"          L3: {packet.Protocol}");

        return packet.PayloadPacket switch
        {
            IPv4Packet p => PrintIPv4Packet(p, sb),
            IPv6Packet p => PrintIPv6Packet(p, sb),
            _ => new FilterData(Filter.None),
        };
    }

    private static FilterData PrintMacFrame(MacFrame packet, StringBuilder sb)
        => new FilterData(Filter.None);

    private static FilterData PrintRadioPacket(
        RadioPacket packet,
        StringBuilder sb
    ) => new FilterData(Filter.None);

    private static FilterData PrintPpiPacket(PpiPacket packet, StringBuilder sb)
        => new FilterData(Filter.None);

    private static FilterData PrintRawIPPacket(
        RawIPPacket packet,
        StringBuilder sb
    ) {
        sb.AppendLine($"          L3: {packet.Protocol}");

        return packet.PayloadPacket switch
        {
            IPv4Packet p => PrintIPv4Packet(p, sb),
            IPv6Packet p => PrintIPv6Packet(p, sb),
            _ => new FilterData(Filter.None),
        };
    }

    // L3

    private static FilterData PrintIPv4Packet(
        IPv4Packet packet,
        StringBuilder sb
    ) {
        sb.AppendLine($"      src IP: {packet.SourceAddress}");
        sb.AppendLine($"      dst IP: {packet.SourceAddress}");
        sb.AppendLine($"          L4: {packet.Protocol}");

        return packet.PayloadPacket switch
        {
            TcpPacket p => PrintTcpPacket(p, sb),
            UdpPacket p => PrintUdpPacket(p, sb),
            IcmpV4Packet p => PrintIcmpV4Packet(p, sb),
            IcmpV6Packet p => PrintIcmpV6Packet(p, sb),
            IgmpPacket p => PrintIgmpPacket(p, sb),
            OspfPacket p => PrintOspfPacket(p, sb),
            IPv4Packet p => PrintIPv4Packet(p, sb),
            IPv6Packet p => PrintIPv6Packet(p, sb),
            GrePacket p => PrintGrePacket(p, sb),
            _ => new FilterData(Filter.None),
        };
    }

    private static FilterData PrintIPv6Packet(
        IPv6Packet packet,
        StringBuilder sb
    ) {
        sb.AppendLine($"      src IP: {packet.SourceAddress}");
        sb.AppendLine($"      dst IP: {packet.SourceAddress}");
        sb.AppendLine($"          L4: {packet.Protocol}");

        return packet.PayloadPacket switch
        {
            TcpPacket p => PrintTcpPacket(p, sb),
            UdpPacket p => PrintUdpPacket(p, sb),
            IcmpV4Packet p => PrintIcmpV4Packet(p, sb),
            IcmpV6Packet p => PrintIcmpV6Packet(p, sb),
            IgmpPacket p => PrintIgmpPacket(p, sb),
            OspfPacket p => PrintOspfPacket(p, sb),
            IPv4Packet p => PrintIPv4Packet(p, sb),
            IPv6Packet p => PrintIPv6Packet(p, sb),
            GrePacket p => PrintGrePacket(p, sb),
            _ => new FilterData(Filter.None),
        };
    }

    private static FilterData PrintArpPacket(
        ArpPacket packet,
        StringBuilder sb
    ) => new FilterData(Filter.None);

    private static FilterData PrintLldpPacket(
        LldpPacket packet,
        StringBuilder sb
    ) => new FilterData(Filter.None);

    private static FilterData PrintPppoePacket(
        PppoePacket packet,
        StringBuilder sb
    ) => packet.PayloadPacket switch
    {
        PppPacket p => PrintPppPacket(p, sb),
        _ => new FilterData(Filter.None),
    };

    private static FilterData PrintWakeOnLanPacket(
        WakeOnLanPacket packet,
        StringBuilder sb
    ) => new FilterData(Filter.None);

    private static FilterData PrintIeee8021QPacket(Ieee8021QPacket packet, StringBuilder sb)
    {
        sb.AppendLine($"          L3: {packet.Type}");

        return packet.PayloadPacket switch
        {
            IPv4Packet p => PrintIPv4Packet(p, sb),
            IPv6Packet p => PrintIPv6Packet(p, sb),
            ArpPacket p => PrintArpPacket(p, sb),
            LldpPacket p => PrintLldpPacket(p, sb),
            PppoePacket p => PrintPppoePacket(p, sb),
            WakeOnLanPacket p => PrintWakeOnLanPacket(p, sb),
            Ieee8021QPacket p => PrintIeee8021QPacket(p, sb),
            _ => new FilterData(Filter.None),
        };
    }

    // L4:

    private static FilterData PrintTcpPacket(
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

    private static FilterData PrintUdpPacket(
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

    private static FilterData PrintIcmpV4Packet(
        IcmpV4Packet packet,
        StringBuilder sb
    ) {
        sb.AppendLine($"        type: {packet.TypeCode}");
        return new(Filter.Icmp4);
    }

    private static FilterData PrintIcmpV6Packet(
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

    private static FilterData PrintIgmpPacket(
        IgmpPacket packet,
        StringBuilder sb
    ) => new(Filter.Igmp);

    private static FilterData PrintOspfPacket(
        OspfPacket packet,
        StringBuilder sb
    ) => new(Filter.None);

    private static FilterData PrintGrePacket(
        GrePacket packet,
        StringBuilder sb
    ) => new(Filter.None);
}
