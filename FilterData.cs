using IpkSniffer.Cli;

namespace IpkSniffer;

public record struct FilterData(
    Filter Categories,
    ushort? AnyPort,
    ushort? SrcPort,
    ushort? DstPort
) {
    public FilterData(Filter categories, ushort? srcPort, ushort? dstPort)
        : this(categories, null, srcPort, dstPort) {}
    public FilterData(Filter categories) : this(categories, null, null) {}

    public readonly bool ShouldShow(FilterData other)
    {
        // Check if filtering should be done
        if (Categories == Filter.None)
            return true;

        var cont = Categories & other.Categories;
        // check if there are correct categories
        if (cont == Filter.None)
            return false;

        // check whether filter also by port
        if ((cont & ~(Filter.Tcp | Filter.Udp)) != Filter.None)
            return true;

        if (AnyPort.HasValue &&
            (AnyPort == other.SrcPort || AnyPort == other.DstPort)
        )
            return true;

        if (SrcPort.HasValue && SrcPort == other.SrcPort)
            return true;

        if (DstPort.HasValue && DstPort == other.DstPort)
            return true;

        return !AnyPort.HasValue && !SrcPort.HasValue && !DstPort.HasValue;
    }
}
