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

import inet.nodes.ipv6.StandardHost6;
import inet.networklayer.autorouting.ipv6.FlatNetworkConfigurator6;
import ned.DatarateChannel;

//import inet.experimental.nodes.adhoc.MobileManetRoutingMesh;
//import inet.experimental.nodes.adhoc.BasicMobileManetMesh;
import inet.world.radio.ChannelControl;


network NetIPv6over802154
{
    types:
        channel C extends DatarateChannel
        {
            //datarate = 250kbps;
            delay = 0.1us;
        }
    submodules:
        channelControl: ChannelControl {
            parameters:
                @display("p=60,50;i=misc/sun");
        }
        configurator: FlatNetworkConfigurator6 {
            parameters:
                @display("p=60,150");
        }

        lrwpanHost1: HostIPv6over802154 {
            parameters:
                @display("p=360,60;i=device/pc3");
        }
        lrwpanHost2: HostIPv6over802154 {
            parameters:
                @display("p=360,155;i=device/pc3");
        }
        lrwpanHost3: HostIPv6over802154 {
            parameters:
                @display("p=360,260;i=device/pc3");
        }
        lrwpanServer: HostIPv6over802154 {
            parameters:
                @display("p=175,75;i=device/pc2");
        }
        hybridRouter: RouterIPv6over802154 {
            parameters:
                @display("p=240,155");
        }
        wiredHost: StandardHost6 {
            @display("p=175,240");
        }
    connections:
        hybridRouter.ethGate <--> C <--> wiredHost.ethg++;
}
