//
// Copyright (C) 2000 Institut fuer Telematik, Universitaet Karlsruhe
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
import inet.nodes.inet.NetworkLayer;

// 802.15.4 MAC / Link Layer
import inet.wpan.linklayer.ieee802154.Ieee802154csmaNic;
import inet.linklayer.ethernet.EthernetInterface;

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
module RouterIPv6over802154
{
    parameters:
        @node();
        @display("i=abstract/router;bgb=308,394");
        string mobilityType;
        string batteryModel @enum("InetSimpleBattery","BasicBattery","") = default("InetSimpleBattery");
    gates:
        input radioIn @directIn;
        inout ethGate;
    submodules:
        notificationBoard: NotificationBoard {
            parameters:
                @display("p=60,49");
        }
        interfaceTable: InterfaceTable {
            parameters:
                @display("p=163,49");
        }
        routingTable6: RoutingTable6 {
            parameters:
                isRouter = true;
                @display("p=257,49");
        }
        networkLayer: NetworkLayer6 {
            parameters:
                @display("p=226,130;q=queue");
            gates:
                ifIn[2];
                ifOut[2];
        }
        eth: EthernetInterface {
            parameters:
                @display("p=130,198,row,110;q=l2queue");
        }
        // MANETRouting disabled because IPv6 nodes lacks MANET routing support
        //        manetrouting: <routingProtocol> like IManetRouting if routingProtocol != "" {
        //            @display("p=159,287");
        //        }
        lrwpan: Ieee802154csmaNic {
            parameters:
                @display("p=226,324;q=queue");
        }
        mobility: <mobilityType> like IMobility {
            parameters:
                @display("p=60,333;i=block/cogwheel");

        }
        disp: Display {
            parameters:
                @display("p=60,261;i=block/app2");

        }
        battery: <batteryModel> like IBattery if batteryModel != "" {
            parameters:
                @display("p=60,130;i=block/plug");

        }
    connections allowunconnected:
        radioIn --> lrwpan.radioIn;
        lrwpan.upperLayerOut --> networkLayer.ifIn[0];
        lrwpan.upperLayerIn <-- networkLayer.ifOut[0];

        ethGate <--> eth.phys;
        eth.upperLayerOut --> networkLayer.ifIn[1];
        eth.upperLayerIn <-- networkLayer.ifOut[1];
}
