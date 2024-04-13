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
            Environment.Exit(Start(Args.Parse(args)));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failure: {ex.Message}");
            Debug.WriteLine(ex);
            Environment.Exit(1);
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

    static int Sniff(Args args) => throw new NotImplementedException();
}
