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
        uint16_t checksum; // Unknown format, increments linearly with pkt_id
    }


    struct vpl_discovery_response {
        uint16_t header; // 0x08 0x00
        uint16_t packet_type; // 0x01 0x00 = discovery poll, 0x02 0x00 = discovery response
        uint16_t pkt_id; // Used to match responses
        uint8_t unknown1; // 0x00 in my captures
        uint16_t product_id; // Model number
    }

    Model number: 0x0407 = VPL610-20. 0x0402 = VPL305-20

    