### IMPI Message

Bytes:

    - rsAddr (SA or SWID) 
    - net Fn / rsLUN
        7-2: netfn
        1-0: LUN
        so netfn of 6 and a LUN of 0 would be 00011000
    - checksum
    - rqAddr (SA or SWID)
    - rqSeq/rqLUN
    - cmd
    - data bytes
    - checksum



## Packet 

*** big endian ordering for rmcp header and asf

*** little endian for imcp header and message


![rcmp](images/rcmp.png)


![packet layers](images/packet_layering.png)

### RMCP Header

![rmcp header](images/rmcp_header.png)

![IPMI v1.5 Session Startup](images/session_startup.png)


### IPMI Message Format

session activation on page 84

![ipmi message format](images/ipmi_msg_format.png)

![ipmi payload detailed](images/ipmi_payload_details.png)

### rqseq

![ipmi payload sensor ids](images/ipmi_payload_sensor.png)

![ipmi system software ids](images/ipmi_payload_software_ids.png)