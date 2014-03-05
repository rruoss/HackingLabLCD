##############################################################################
# OpenVAS Vulnerability Test
#
# Simple TCP portscanner written in pure NASL
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
tag_summary = "This plugin performs TCP portscan.";


if(description)
{
 script_id(80112);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-17 00:41:53 +0200 (Thu, 17 Jun 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None"); 
 name = "Simple TCP portscan in NASL";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Performs portscan";
 script_summary(summary);
 
 script_category(ACT_SCANNER);
 
 script_copyright("This script is Copyright (C) 2010 Vlatko Kosturjak");
 family = "Port scanners";
 script_family(family);

 script_add_preference(name:"Portscan wait time", type:"entry", value: "");
 script_add_preference(name:"Portscan time out", type:"entry", value: "");
 script_add_preference(name:"Do not randomize the order in which ports are scanned", type:"checkbox", value: "no");
 script_dependencies("ping_host.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

if (! experimental_scripts) {
	log_message(port:0,proto:"tcp",data:"This portscanner is EXPERIMENTAL and you should NOT RELY ON it if you don't know what you're doing. If you are sure what you're doing - you should turn on experimental_scripts option in preferences in order to turn off this warning.");
}

wait = script_get_preference("Portscan wait time");
timeout = script_get_preference("Portscan time out");
function checkport(port) {
	local_var sock;	
#	display(port + " " + typeof(port)+ " : ");
	usleep(wait);
	sock = open_sock_tcp(port,timeout:timeout);
	if (! sock) {
#		display("closed\n");
		return (FALSE);
	} else {
#		display("open\n");
		close(sock);
		return (TRUE);
	}
}

proto="tcp";
prange = get_preference("port_range");

if (! prange) prange = "1-65535"; 
if (prange == "default" )
{
	n = 0;
	str = "";
	while ( port = scanner_get_port(n) )
	{
		if ( n > 0 ) str += "," + string(port);
		else str = string(port);
		n ++;
	}
	prange=str;
}

portrangelist=split(prange,sep:",",keep:FALSE);

p = 0;
tcp = 1;

foreach pr (portrangelist) {

 prs = split (pr,sep:"-",keep:FALSE);

 if (substr (prs[0], 0, 1) == "U:") {
	# Skip UDP ranges.
	tcp = 0;
 } else {
	if ((strlen (prs[0]) > 1) && (substr (prs[0], 0, 1) == "T:")) {
		# Strip off the "T:".
		prs[0] = substr (prs[0], 2);
		tcp = 1;
	}

	if (tcp == 0)
		# Skip UDP ranges.
		continue;
	if (isnull(prs[1])) {
		i=int(prs[0]);
		ports[p] = i;
		p++;
	} else {
		begport=int(prs[0]);
		endport=int(prs[1]);
		# swap vars if last is bigger than first
		if (begport>endport) {
			tmpvar = endport;
			endport = begport;
			begport = tmpvar;
		}
		for (i=begport; i<=endport; i++) {
			ports[p] = i;
			p++;
		}
	} # if () range or single port
 } # if () UDP or TCP
} # foreach

# to randomize port order to scan?
randomize= script_get_preference("Do not randomize the order in which ports are scanned");
if ("yes" >< randomize) { 
	# do not randomize = do nothing, this is just placeholder
	# to make it default to randomize in command line (openvas-nasl)
} else {
	# randomize port order to scan
	for (j=0; j<p; j++) {
		r1 = rand() % p;
		r2 = rand() % p;	
		xval = ports[r1];
		ports[r1] = ports[r2];
		ports[r2] = xval;
	}
}

n_ports = 0;
c_ports = 0;
foreach port (ports) {
	if (checkport(port:port)) {
		scanner_add_port(proto: proto, port: port);
		n_ports++;
	}
	scanner_status(current: c_ports, total: p);
	c_ports++;
}

if (n_ports == 0) {
	log_message(port:0,proto:"tcp",data:"Host does not have any TCP port open in given port range.");
} else {
	log_message(port:0,proto:"tcp",data:"Host have "+n_ports+" TCP port(s) open in given port range. ");
}

set_kb_item(name: "Host/scanned", value: TRUE);
set_kb_item(name: 'Host/scanners/simpletcpnasl', value: TRUE);
if (prange == '1-65535')
  set_kb_item(name: "Host/full_scan", value: TRUE);

scanner_status(current: 65535, total: 65535);

exit (0);

