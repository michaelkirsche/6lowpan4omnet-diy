//
// Copyright (C) 2012 Computer Networks and Communication Systems Group, BTU Cottbus
//               @ Jonas Hartwig and Michael Kirsche
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

network NetTwoNodes
{
    types:
    submodules:
        channelControl: ChannelControl {
            parameters:
                @display("p=60,50;i=misc/sun");
        }
        configurator: FlatNetworkConfigurator6 {
            parameters:
                @display("p=60,120");
        }
        lrwpanHost1: HostIPv6over802154 {
            parameters:
                @display("p=185,140;i=device/pc3");
        }
        lrwpanHost2: HostIPv6over802154 {
            parameters:
                @display("p=300,140;i=device/pc3");
        }
        hybridRouter: Router802154 {
            parameters:
                @display("p=240,70");
        }
    connections:
}