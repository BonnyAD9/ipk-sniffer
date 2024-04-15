using System.Diagnostics;
using System.Text;
using System.Xml;
using IpkSniffer.Cli;
using PacketDotNet;
using PacketDotNet.Ieee80211;
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
            EthernetPacket p => L2.PrintEthernetPacket(p, sb),
            LinuxSllPacket p => L2.PrintLinuxSllPacket(p, sb),
            NullPacket p => L2.PrintNullPacket(p, sb),
            PppPacket p => L2.PrintPppPacket(p, sb),
            MacFrame p => L2.PrintMacFrame(p, sb),
            RadioPacket p => L2.PrintRadioPacket(p, sb),
            PpiPacket p => L2.PrintPpiPacket(p, sb),
            RawIPPacket p => L2.PrintRawIPPacket(p, sb),
            _ => new(Filter.None),
        };
    }
}
