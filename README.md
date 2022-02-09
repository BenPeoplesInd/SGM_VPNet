# SGM_VPNet
Reverse engineering and writing a library for SGM VPNet (SGM VPL specifically)


# Discovery Packets

SGM Network Admin (SNA) sends packets on UDP ports 21319 broadcast to 255.255.255.255 in identical pairs with less than a millisecond delay between them.   

These packets carry the payload:

    0000   08 00 01 00 7e 00 00 00 00 c0 bb

They also send discovery packets to 62997 (different packets, different format).   I suspect these are for a different product line as the VPL do not respond to this.

VPL responds with a directed UDP packet to the 21319 port as follows:

    0000   08 00 02 00 80 00 00 04 07 00

    0000   08 00 02 00 80 00 00 04 02 00

Proposed format (Little Endian):

    struct vpl_discovery_poll {
        uint16_t header; // 0x08 0x00
        uint16_t packet_type; // 0x01 0x00 = discovery poll, 0x02 0x00 = discovery response
        uint16_t pkt_id; // Used to match responses
        uint8_t unknown1; // Always 0x00
        uint8_t unknown2; // Always 0x00
        uint8_t unknown3; // Always 0x00
        uint16_t poller_tag; // this identifies the poller for discovery mute purposes
    }

    struct vpl_discovery_response {
        uint16_t header; // 0x08 0x00
        uint16_t packet_type; // 0x01 0x00 = discovery poll, 0x02 0x00 = discovery response
        uint16_t pkt_id; // Used to match responses
        uint8_t unknown1; // 0x00 in my captures
        uint16_t product_id; // Model number
        uint8_t unknown2; // 0x00 in my captures
    }

    Model number: 0x04 0x07 = VPL610-20. 0x04 0x02 = VPL305-20


# Discovery Mute

The last two octets of the discovery poll packet are a tag that allows the sender to mute fixtures for a particular sender, and then fire up a new pair of octets when they want to discover again.   

The discovery mute command is 0x000f:

    0000   08 00 0f 00 83 00 00 00 07 00 03 00 c2 bb 01

Packet format is this:

    struct discovery_mute_request {
        uint16_t header; // 0x08 0x00
        uint16_t packet_type; // 0x01 0x00 = discovery poll, 0x02 0x00 = discovery response
        uint16_t pkt_id; // Used to match responses
        uint8_t unknown1; // Always 0x00
        uint8_t unknown2; // Always 0x00
        uint8_t unknown3; // Always 0x00
        uint16_t unknown4; // always 0x0007 in my captures
        uint16_t unknown5; // always 0x0003 in my captures
        uint16_t poller_tag; // this identifies the poller for discovery mute purposes
        uint8_t flag; // assume 0x01 = enabled, 0x00 = disable
    }

The response is this:

    0000   08 00 10 00 83 00 00 04 07 00 00 47 4d 00 00 01
    0010   4c 36 31 30 2d 32 30

Which is clearly packet_type 0x0010 but I'm not sure the format of this or why it's the response to the discovery mute command.


# Sensor packets

We primarily think that the sensor packets will be useful in Horatio-land, so that's the next target.  There seems to be a LOT of packets between discovery and monitoring, including some sort of discovery-mute flag (possibly packet_type `0x0003` because this is the next packet sent after discovery).

## Sensor Poll (0x0007)

    0000   08 00 07 00 53 01 00 00 00 01 02 03

This is sent from SNA to each fixture individually, packet format is very similar to the other command packets:

    struct vpl_sensor_poll {
        uint16_t header; // 0x08 0x00
        uint16_t packet_type; // 0x07 0x00 = sensor poll
        uint16_t pkt_id; // Used to match responses
        uint8_t unknown1; // Always 0x00
        uint8_t unknown2; // Always 0x00
        uint8_t sensor0; // 0x00
        uint8_t sensor1; // 0x01
        uint8_t sensor2; // 0x02
        uint8_t sensor3; // 0x03
    }

## Sensor response (0x0008)

The response to this is a packet with sensor data:

    0000   08 00 08 00 53 01 00 04 00 90 6f 71 41 d0 ac 6b
    0010   41 9c c8 16 42 01 90 42 6c 41 50 ce 65 41 c4 41
    0020   03 42 02 cd 84 44 41 9a db 43 41 66 aa 44 41 03
    0030   00 00 00 00 00 00 00 00 00 00 00 00

This clearly consists of tagged fields of *probably* IEEE floating point numbers (certainly 32-bit numbers), but let's give it a go:

    0800 = header
    0800 = pkt type 0x0008
    5301 = sequence number
    00 = pad byte? always 0x00
    04 = how many sensor fields we have?
    00 = sensor 0 (Main temp)
    906f7141 = Float - Little Endian (DCBA)	= 15.0897369 (Value)
    d0ac6b41 = 14.7296906 (Min)
    9cc81642 = 37.6959076 (Max)
    01 = sensor 1 (LED temp)
    90426c41 = 14.7662506
    50ce6541 = 14.3628693
    c4410342 = 32.8142242
    02 = sensor 2 (V LED)
    cd844441 = 12.2824221
    9adb4341 = 12.2411137
    66aa4441 = 12.2916012
    03 = sensor 3 (FPS)
    00000000 = 0 
    00000000 = 0
    00000000 = 0

    struct vpl_sensor_data {
        uint16_t header; // 0x08 0x00
        uint16_t packet_type; // 0x08 0x00 = sensor poll
        uint16_t pkt_id; // Used to match responses
        uint8_t unknown1; // Always 0x00
        uint8_t sensor_count; // Always 0x04
        struct sensor_data data[4];
    }

    struct sensor_data {
        uint8_t sensor_id;
        float value; // current value Float - Little Endian (DCBA)
        float min; // lowest recorded value
        float max; // highest recorded value
    }



# Other interesting tidbits

Just looking for strings, these are packet_types:

0x000c - a bunch of enums getting reported?  All the things in the dropdown menus are here

0x000e - modes looks like?

0x0005 - sensor description requests

0x0006 - sensor descriptions here

