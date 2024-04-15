namespace IpkSniffer.Cli;

class Args
{
    public int ArgCount { get; init; }
    private Action? action = null;
    public Action Action => action ?? Action.List;
    public string Interface { get; private set; } = "";
    public ushort? AnyPort { get; private set; } = null;
    public ushort? DstPort { get; private set; } = null;
    public ushort? SrcPort { get; private set; } = null;
    public Filter Filter { get; private set; }
    public nuint PacketCount { get; private set; } = 1;

    private Args(int count)
    {
        ArgCount = count;
    }

    public static Args Parse(ReadOnlySpan<string> args)
    {
        Args res = new(args.Length);
        res.ParseArgs(args);
        res.ValidateArgs();
        return res;
    }

    private void ValidateArgs()
    {
        if (!action.HasValue)
        {
            if (ArgCount != 0)
                throw new ArgumentException("Missing interface (use '-i').");
            action = Action.List;
        }

        if ((DstPort.HasValue || SrcPort.HasValue)
            && !Filter.HasFlag(Filter.Tcp)
            && !Filter.HasFlag(Filter.Udp)
        )
            throw new ArgumentException("Filtering port has no effect.");

        if (PacketCount <= 0)
            throw new ArgumentException(
                "Invalid number of packets to capture. "
                    + "Number must be positive."
            );
    }

    private void ParseArgs(ReadOnlySpan<string> args)
    {
        while (args.Length > 0)
        {
            var arg = args[0];
            switch (arg)
            {
                // In switch:
                //   Use break when one argument is processed but not taken
                //     from args.
                //   Use continue when all processed arguments are taken from
                //     args.
                case "-i" or "--interface":
                    if (ArgCount == 1)
                    {
                        action = Action.List;
                        break;
                    }
                    Interface = TakeSecond(ref args);
                    if (Interface == "")
                        throw new ArgumentException(
                            "Invalid interface. Cannot be empty string."
                        );
                    action = Action.Sniff;
                    continue;
                case "-t" or "--tcp":
                    Filter |= Filter.Tcp;
                    break;
                case "-u" or "--udp":
                    Filter |= Filter.Udp;
                    break;
                case "-p":
                    AnyPort = ParseSecond<ushort>(ref args);
                    continue;
                case "--port-destination":
                    DstPort = ParseSecond<ushort>(ref args);
                    continue;
                case "--port-source":
                    SrcPort = ParseSecond<ushort>(ref args);
                    continue;
                case "--icmp4":
                    Filter |= Filter.Icmp4;
                    break;
                case "--icmp6":
                    Filter |= Filter.Icmp6;
                    break;
                case "--arp":
                    Filter |= Filter.Arp;
                    break;
                case "--ndp":
                    Filter |= Filter.Ndp;
                    break;
                case "--igmp":
                    Filter |= Filter.Igmp;
                    break;
                case "--mld":
                    Filter |= Filter.Mld;
                    break;
                case "-n":
                    PacketCount = ParseSecond<nuint>(ref args);
                    continue;
                default:
                    throw new ArgumentException($"Unknown argument {arg}");
            }
            args = args[1..];
        }
    }

    private string TakeSecond(ref ReadOnlySpan<string> args)
    {
        if (args.Length < 2)
            throw new ArgumentException(
                $"Expected another argument after {args[0]}."
            );
        var res = args[1];
        args = args[2..];
        return res;
    }

    private T ParseSecond<T>(ref ReadOnlySpan<string> args) where T : IParsable<T>
    {
        var arg = args[0];
        if (T.TryParse(TakeSecond(ref args), null, out T? res))
            return res;
        throw new ArgumentException(
            $"Failed to parse argument to {arg} to type {typeof(T).Name}."
        );
    }
}
