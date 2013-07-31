//
// Copyright (C) 2013 Michael Kirsche
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

package inet.examples.wpan.sixlowpan;

// Internet
import inet.networklayer.ipv6.RoutingTable6;
import inet.nodes.ipv6.NetworkLayer6;
//import inet.nodes.inet.NetworkLayer;

// IEEE 802.15.4 MAC / Link Layer
import inet.wpan.linklayer.ieee802154.Ieee802154csmaNic;

// Additional Modules
import inet.networklayer.common.InterfaceTable;
import inet.base.NotificationBoard;
import inet.mobility.IMobility;
import inet.networklayer.IManetRouting;
import inet.battery.IBattery;
import inet.wpan.Isabel.Base.Display;

//
// \IPv6 router.
//
module Router802154
{
    parameters:
        @node();
        @display("i=abstract/router;bgb=324,377");
        string mobilityType;
        string batteryModel @enum("InetSimpleBattery","BasicBattery","") = default("InetSimpleBattery");  // used mobile routing protocol. see: inet.networklayer.manetrouting

    gates:
        input radioIn @directIn;

    submodules:
        notificationBoard: NotificationBoard {
            parameters:
                @display("p=60,60");
        }
        interfaceTable: InterfaceTable {
            parameters:
                @display("p=174,60");
        }
        routingTable6: RoutingTable6 {
            parameters:
                isRouter = true;
                @display("p=275,60");
        }
        networkLayer: NetworkLayer6 {
            parameters:
                @display("p=216,143;q=queue");
            gates:
                ifIn[2];
                ifOut[2];
        }
        // MANETRouting disabled because IPv6 nodes lacks MANET routing support
        //        manetrouting: <routingProtocol> like IManetRouting if routingProtocol != "" {
        //            @display("p=159,287");
        //        }
        lrwpan: Ieee802154csmaNic {
            parameters:
                @display("p=216,296;q=queue;i=block/ifcard");
        }
        mobility: <mobilityType> like IMobility {
            parameters:
                @display("p=135,214;i=block/cogwheel");

        }
        disp: Display {
            parameters:
                @display("p=60,220;i=block/app2");

        }
        battery: <batteryModel> like IBattery if batteryModel != "" {
            parameters:
                @display("p=60,143;i=block/plug");

        }
    connections allowunconnected:
        radioIn --> lrwpan.radioIn;
        lrwpan.upperLayerOut --> networkLayer.ifIn[0];
        lrwpan.upperLayerIn <-- networkLayer.ifOut[0];
}
