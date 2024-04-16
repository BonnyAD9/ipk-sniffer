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
        // Make sure there is an action to take
        if (!action.HasValue)
        {
            if (ArgCount != 0)
                throw new ArgumentException("Missing interface (use '-i').");
            action = Action.List;
        }

        // Throw error when port filters are set but they would have no effect
        if ((DstPort.HasValue || SrcPort.HasValue)
            && !Filter.HasFlag(Filter.Tcp)
            && !Filter.HasFlag(Filter.Udp)
        )
            throw new ArgumentException("Filtering port has no effect.");

        // check for valid value of the number of packets to capture
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
                    // Empty value is not a valid interface
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

    /// <summary>
    /// Returns the second value in the span and pops the first two values from
    /// the span.
    /// </summary>
    /// <param name="args">The span to operate on</param>
    /// <returns>The second value in the span</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when there are not enough values in the span.
    /// </exception>
    private static string TakeSecond(ref ReadOnlySpan<string> args)
    {
        if (args.Length < 2)
            throw new ArgumentException(
                $"Expected another argument after {args[0]}."
            );
        var res = args[1];
        args = args[2..];
        return res;
    }

    /// <summary>
    /// Takes the second value from the span, parses it into the given type and
    /// pops the first two values from the span.
    /// </summary>
    /// <typeparam name="T">Type to parse to.</typeparam>
    /// <param name="args">The span to operate on.</param>
    /// <returns>
    /// The second value from the span parsed to the given type
    /// </returns>
    /// <exception cref="ArgumentException">
    /// When span is too short or the value couldn't be parsed
    /// </exception>
    private static T ParseSecond<T>(ref ReadOnlySpan<string> args) where T : IParsable<T>
    {
        var arg = args[0];
        if (T.TryParse(TakeSecond(ref args), null, out T? res))
            return res;
        throw new ArgumentException(
            $"Failed to parse argument to {arg} to type {typeof(T).Name}."
        );
    }
}
