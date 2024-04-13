using System.Diagnostics;
using IpkSniffer.Cli;
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

    static int Sniff(Args args)
    {
        var device = CaptureDeviceList
            .Instance
            .First(d => d.Name == args.Interface);

        maxCount = args.PacketCount;

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

        return 1;
    }

    static void CapturePacket(object sender, PacketCapture packet)
    {
        if (count >= maxCount)
            return;
        count += 1;
        // TODO
        Console.WriteLine("Recieved packet");
    }
}
