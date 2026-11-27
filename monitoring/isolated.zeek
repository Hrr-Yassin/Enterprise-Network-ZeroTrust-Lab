@load base/protocols/conn
@load base/protocols/dns

redef LogAscii::use_json = T;

# Let a single synthetic DNS exchange close within the guest acceptance window.
redef udp_inactivity_timeout = 5sec;
