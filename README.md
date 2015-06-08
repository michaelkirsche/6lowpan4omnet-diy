6LoWPAN for OMNeT++ - *Integrate It Yourself* Version
=====================================================
  
This repository contains the [*Integrate It Yourself*](#integrate-it-yourself) version of a 6LoWPAN simulation model for the [OMNeT++](http://www.omnetpp.org/) simulation framework. The model itself integrates [Contiki's](http://www.contiki-os.org/) 6LoWPAN implementation into OMNeT++. Refer to [the paper](#publication) for more information about the basics and our generic approach.


## Integrate It Yourself ##

*Integrate It Yourself Version* means that you have to perform the integration of the model in OMNeT++ / INET / INETMANET / Contiki step-by-step by yourself (therefore DIY). An installation and configuration tutorial can be found at the [Wiki page on Github](https://github.com/michaelkirsche/6lowpan4omnet-diy/wiki), along with answers to [frequency asked questions](https://github.com/michaelkirsche/6lowpan4omnet-diy/wiki/FAQ).


## Directory Structure ##

The directory structure reflects the integration steps, refer to the instruction / installation description for further information.

 1. `contiki_platform_omnet`: includes the OMNeT++ platform definition for Contiki v2.6
 2. `contiki_adjustments`: includes fixes / patches and adjustments for Contiki v2.6 to support the OMNeT++ integration
 3. `6lowpan_wrapper`: wrapper for INET v2.x and INETMANET2
 4. `examples`: example simulations for INET v2.x and INETMANET2
 

## Releases ##

Releases are published in this Github repository in the *Integrate It Yourself* version and in [the *Clone It Yourself* version](https://github.com/michaelkirsche/6lowpan4omnet-diy/wiki/Clone-It-Yourself-Version) in the according branches of [my INET/INETMANET and Contiki clones](https://github.com/michaelkirsche).


## Publication ##

If you are interested in background information, please refer to the following publication:

 * Kirsche, M.; Hartwig, J.: [*A 6LoWPAN Model for OMNeT++*](http://www-docs.tu-cottbus.de/rechnernetze/public/staff/mkirsche/publications/SIMUTools_2013-OMNeT-Kirsche_Hartwig.pdf), in Proceedings of the [6th International OMNeT++ Workshop](https://workshop.omnetpp.org/2013/), co-located with the [6th International ICST Conference on Simulation Tools and Techniques (SIMUTools 2013)](http://simutools.org/2013/), March 2013. 


## Contributors ##

 * &copy; Michael Kirsche (michael.kirsche(at)b-tu.de)
 * Jonas Hartwig
