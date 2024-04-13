namespace IpkSniffer.Cli;

[Flags]
public enum Filter : uint
{
    None = 0x0,
    Tcp = 0x1,
    Udp = 0x2,
    Icmp4 = 0x4,
    Icmp6 = 0x8,
    Arp = 0x10,
    Ndp = 0x20,
    Igmp = 0x40,
    Mld = 0x80,
    All = 0xFF,
}
