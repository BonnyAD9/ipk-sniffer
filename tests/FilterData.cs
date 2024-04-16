using IpkSniffer;
using IpkSniffer.Cli;

namespace Tests;

public class FilterDataTests
{
    [Fact]
    public static void TestFilterNone()
    {
        var filter = new FilterData(Filter.None);

        Assert.True(filter.ShouldShow(new(Filter.None)));
        Assert.True(filter.ShouldShow(new(Filter.Tcp)));
        Assert.True(filter.ShouldShow(new(Filter.Icmp4)));
        Assert.True(filter.ShouldShow(new(Filter.Udp, 123, 456)));
        Assert.True(filter.ShouldShow(new(Filter.Ndp | Filter.Icmp6)));
        Assert.True(filter.ShouldShow(new(Filter.Mld | Filter.Icmp6)));
        Assert.True(filter.ShouldShow(new(Filter.Icmp6)));
    }

    [Fact]
    public static void TestFilterSimple()
    {
        var filter = new FilterData(Filter.Icmp4);

        Assert.True(filter.ShouldShow(new(Filter.Icmp4)));

        Assert.False(filter.ShouldShow(new(Filter.None)));
        Assert.False(filter.ShouldShow(new(Filter.Tcp)));
        Assert.False(filter.ShouldShow(new(Filter.Udp, 123, 456)));
        Assert.False(filter.ShouldShow(new(Filter.Ndp | Filter.Icmp6)));
        Assert.False(filter.ShouldShow(new(Filter.Mld | Filter.Icmp6)));
        Assert.False(filter.ShouldShow(new(Filter.Icmp6)));
    }

    [Fact]
    public static void TestFilterIcmp6()
    {
        var filter = new FilterData(Filter.Icmp6);

        Assert.True(filter.ShouldShow(new(Filter.Ndp | Filter.Icmp6)));
        Assert.True(filter.ShouldShow(new(Filter.Mld | Filter.Icmp6)));
        Assert.True(filter.ShouldShow(new(Filter.Icmp6)));

        Assert.False(filter.ShouldShow(new(Filter.None)));
        Assert.False(filter.ShouldShow(new(Filter.Tcp)));
        Assert.False(filter.ShouldShow(new(Filter.Icmp4)));
        Assert.False(filter.ShouldShow(new(Filter.Udp, 123, 456)));
    }

    [Fact]
    public static void TestFilterNdp()
    {
        var filter = new FilterData(Filter.Ndp);

        Assert.True(filter.ShouldShow(new(Filter.Ndp | Filter.Icmp6)));

        Assert.False(filter.ShouldShow(new(Filter.None)));
        Assert.False(filter.ShouldShow(new(Filter.Tcp)));
        Assert.False(filter.ShouldShow(new(Filter.Icmp4)));
        Assert.False(filter.ShouldShow(new(Filter.Udp, 123, 456)));
        Assert.False(filter.ShouldShow(new(Filter.Mld | Filter.Icmp6)));
        Assert.False(filter.ShouldShow(new(Filter.Icmp6)));
    }

    [Fact]
    public static void TestFilterMultiple()
    {
        var filter = new FilterData(Filter.Ndp | Filter.Icmp4 | Filter.Tcp);

        Assert.True(filter.ShouldShow(new(Filter.Tcp)));
        Assert.True(filter.ShouldShow(new(Filter.Icmp4)));
        Assert.True(filter.ShouldShow(new(Filter.Ndp | Filter.Icmp6)));

        Assert.False(filter.ShouldShow(new(Filter.None)));
        Assert.False(filter.ShouldShow(new(Filter.Udp, 123, 456)));
        Assert.False(filter.ShouldShow(new(Filter.Mld | Filter.Icmp6)));
        Assert.False(filter.ShouldShow(new(Filter.Icmp6)));
    }

    [Fact]
    public static void TestFilterIpAddressAny()
    {
        var filter = new FilterData(Filter.Tcp, 123, null, null);

        Assert.True(filter.ShouldShow(new(Filter.Tcp, 123, 456)));
        Assert.True(filter.ShouldShow(new(Filter.Tcp, 456, 123)));

        Assert.False(filter.ShouldShow(new(Filter.None)));
        Assert.False(filter.ShouldShow(new(Filter.Tcp)));
        Assert.False(filter.ShouldShow(new(Filter.Icmp4)));
        Assert.False(filter.ShouldShow(new(Filter.Udp, 123, 456)));
        Assert.False(filter.ShouldShow(new(Filter.Ndp | Filter.Icmp6)));
        Assert.False(filter.ShouldShow(new(Filter.Mld | Filter.Icmp6)));
        Assert.False(filter.ShouldShow(new(Filter.Icmp6)));
    }

    [Fact]
    public static void TestFilterIpAddressOne()
    {
        var filter = new FilterData(Filter.Tcp | Filter.Udp, 123, null);

        Assert.True(filter.ShouldShow(new(Filter.Tcp, 123, 456)));
        Assert.True(filter.ShouldShow(new(Filter.Udp, 123, 456)));

        Assert.False(filter.ShouldShow(new(Filter.None)));
        Assert.False(filter.ShouldShow(new(Filter.Tcp)));
        Assert.False(filter.ShouldShow(new(Filter.Icmp4)));
        Assert.False(filter.ShouldShow(new(Filter.Ndp | Filter.Icmp6)));
        Assert.False(filter.ShouldShow(new(Filter.Mld | Filter.Icmp6)));
        Assert.False(filter.ShouldShow(new(Filter.Icmp6)));
        Assert.False(filter.ShouldShow(new(Filter.Tcp, 456, 123)));
    }

    [Fact]
    public static void TestFilterAny()
    {
        var filter = new FilterData(
            Filter.Tcp | Filter.Udp | Filter.Icmp4 | Filter.Ndp,
            789,
            123,
            456
        );

        Assert.True(filter.ShouldShow(new(Filter.Tcp, 123, 456)));
        Assert.True(filter.ShouldShow(new(Filter.Udp, 123, 456)));
        Assert.True(filter.ShouldShow(new(Filter.Udp, 156, 456)));
        Assert.True(filter.ShouldShow(new(Filter.Udp, 789, 654)));
        Assert.True(filter.ShouldShow(new(Filter.Icmp4)));
        Assert.True(filter.ShouldShow(new(Filter.Ndp | Filter.Icmp6)));

        Assert.False(filter.ShouldShow(new(Filter.None)));
        Assert.False(filter.ShouldShow(new(Filter.Tcp)));
        Assert.False(filter.ShouldShow(new(Filter.Mld | Filter.Icmp6)));
        Assert.False(filter.ShouldShow(new(Filter.Icmp6)));
        Assert.False(filter.ShouldShow(new(Filter.Tcp, 456, 123)));
        Assert.False(filter.ShouldShow(new(Filter.Udp, 894, 654)));
    }

    [Fact]
    public static void TestFilterAll()
    {
        var filter = new FilterData(Filter.All);

        Assert.True(filter.ShouldShow(new(Filter.Tcp)));
        Assert.True(filter.ShouldShow(new(Filter.Icmp4)));
        Assert.True(filter.ShouldShow(new(Filter.Udp, 123, 456)));
        Assert.True(filter.ShouldShow(new(Filter.Ndp | Filter.Icmp6)));
        Assert.True(filter.ShouldShow(new(Filter.Mld | Filter.Icmp6)));
        Assert.True(filter.ShouldShow(new(Filter.Icmp6)));

        Assert.False(filter.ShouldShow(new(Filter.None)));
    }
}
