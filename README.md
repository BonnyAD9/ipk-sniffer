# ipk-sniffer

## Contents
TODO

## About
This project is implementation of a network sniffer in C#. It can capture and
display any type of packet and it can also filter some packets. Various
different packet types are recognized, but only some specific additional
information is displayed.

I decided to implement this project in C# because I know the language well.

The implementation uses the library *SharpPcap* for capturing packets and
*PacketDotNet* for parsing the packets.

## Code structure
The code is divided into 2 namespaces:
- `IpkSniffer`: the main namespace with most of the logic.
- `IpkSniffer.Cli`: contains structures and logic for parsing command line
  arguments

### `IpkSniffer`
This namespace is the base of the project. It contains the `Main` function and
logic for printing the packet information to the console.

It is divided into 5 files:
- `Program.cs`: the entry point, contains mostly logic for capturing the
  packets.
- `FilterData.cs`: contains the filtering logic.
- `L2.cs`, `L3.cs`, `L4.cs`: These contain functions for printing information
  about packets. Each file contains logic for the printing of packets in the
  specific layer.

#### `FilterData.cs`
This file contains class that represents either a filter or data to be
filtered. The filter consists of flags and optional port numbers. The filtering
is done in the method `FilterData.ShouldShow` which is called on a filter where
argument to this function is representation of the data to be filtered. It
returns `true` if the data passes the filter (should be shown to the user),
and `false` if the data doesn't pass the filter (shouldn't be shown to the
user).

### `IpkSniffer.Cli`
Here is contained the logic for parsing the arguments. There are two
enumerations (`Action` and `Filter`).

`Action` represents the action to be
taken. It can be either to sniff (capture packets) or to list all available
interfaces.

`Filter` represents the flags of the filter. If filter is `None`, packets are
not filtered. Otherwise only packets that are set in the filter are shown.

The class `Args` contains the data parsed from the arguments and it contains
the logic for parsing the arguments.
