# OpenVAS Vulnerability Test
# $Id: nortel_annex_default_pass.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Nortel/Bay Networks/Xylogics Annex default password
#
# Authors:
# Douglas Minderhout <dminderhout@layer3com.com>
# Based upon a script by Rui Bernardino <rbernardino@oni.pt>
#
# Copyright:
# Copyright (C) 2003 Douglas Minderhout
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote terminal server has the default password set.
This means that anyone who has (downloaded) a user manual can
telnet to it and gain administrative access.

If modems are attached to this terminal server, it may allow
unauthenticated remote access to the network.";

tag_solution = "Telnet to this terminal server change to the root
user with 'su' and set the password with the 'passwd' command.
Then, go to the admin mode using the 'admin' command. Cli 
security can then be enabled by setting the vcli_security to
'Y' with the command 'set annex vcli_security Y'. This will
require ERPCD or RADIUS authentication for access to the 
terminal server. Changes can then be applied through the
'reset annex all' command.";

if(description)
{
        script_id(11201);
        script_version("$Revision: 17 $");
        script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
        script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
        script_tag(name:"cvss_base", value:"7.8");
        script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
        script_tag(name:"risk_factor", value:"High");
        name = "Nortel/Bay Networks/Xylogics Annex default password";
        script_name(name);

        desc = "
        Summary:
        " + tag_summary + "
        Solution:
        " + tag_solution;
        script_description(desc);

        summary = "Logs into the remote Nortel terminal server";
        script_summary(summary);

        script_category(ACT_ATTACK);

        script_copyright("This script is Copyright (C) 2003 Douglas Minderhout");
        family = "General";
        script_family(family);
        script_require_ports(23);

        if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
          script_tag(name : "solution" , value : tag_solution);
          script_tag(name : "summary" , value : tag_summary);
        }
        exit(0);
}

include('telnet_func.inc');


function myrecv(socket, pattern) {
	while(1) {
		r = recv_line(socket:soc, length:1024);
		if(strlen(r) == 0) return(0);
		if(ereg(pattern:pattern, string:r)) return(r);
	}
}



#
# The script code starts here
#
port = 23;

banner = get_telnet_banner(port:port);
if ( ! banner || "Annex" >!< banner ) exit(0);

if(get_port_state(port)) {


	soc=open_sock_tcp(port);
	if(!soc)exit(0);
	buf=telnet_negotiate(socket:soc);
	#display(buf);
	nudge = string("\r\n");
	send(socket:soc, data:nudge);
	# Since the Annex is unkind enough to not send a login banner,  we nudge the remote host and see if it's an Annex
	# The response to the nudge should be a list of ports and a line with the word Annex in it.
	resp = recv(socket:soc, length:1024);
	#display(resp);
	# If we catch one of these, it's something else
	if("NetLogin:" >< resp)exit(0);
	if("Login:" >< resp)exit(0);
	# If we get Annex in the response we're in business
	if ("Annex" >< resp) {
		# Here we send it the cli command, requesting a command prompt
		test = string("cli\r\n");
		send(socket:soc, data:test);
		#resp = recv(socket:soc, length:1024);
		resp = myrecv(socket:soc, pattern:".*annex:.*");
		#display(resp);
		if("annex:" >< resp) {
			# If we get here, it means that CLI security is disabled and the annex does not require a password
			desc = string ("CLI Security is disabled on the Annex");
			security_hole(port:port, data:desc);
			# Now we try to 'su'
			test = string("su\r\n");
			send(socket:soc, data:test);
			#resp = recv_line(socket:soc, length:1024);
			resp = myrecv(socket:soc, pattern:".*assword:.*");
			#display(resp);
			if("assword:" >< resp) {
				# The default 'su' password is the IP address of the box
				ip = get_host_ip();
				test = string(ip,"\r\n");
				send(socket:soc, data:test);
				#resp = recv_line(socket:soc, length:1024);
				resp = myrecv(socket:soc, pattern:".*annex#.*");
				#display(resp);
				if("annex#" >< resp) {
					# The prompt changes to 'annex#' when we're supeuser
					desc = string ("The SuperUser password is at it's default setting.");
					security_hole(port:port, data:desc);
				}
			}
		}
	close (soc);
	}
} 
