# OpenVAS Vulnerability Test
# $Id: cisco_default_pw.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Cisco default password
#
# Authors:
# Javier Fernandez-Sanguino
# based on a script written by Renaud Deraison <deraison@cvs.nessus.org>
# with contributions by Gareth M Phillips <gareth@sensepost.com> (additional logins and passwords)
#
# Copyright:
# Copyright (C) 2001 - 2006 Javier Fernandez-Sanguino and Renaud Deraison
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
tag_summary = "The remote device has a factory password set.

Description :

The remote CISCO router has a default password set.  
This allows an attacker to get a lot information
about the network, and possibly to shut it down if
the 'enable' password is not set either or is also a default
password.";

tag_solution = "Access this device and set a password using 'enable secret'";

# TODO:
# - dump the device configuration to the knowdledge base (requires
#   'enable' access being possible)
# - store the CISCO IOS release in the KB so that other plugins (in the Registered
#   feed) could use the functions in cisco_func.inc to determine if the system is
#   vulnerable as is currently done through SNMP (all the CSCXXXX.nasl stuff)
# - store the user/password combination in the KB and have another plugin test
#   for common combinations that lead to 'enable' mode.

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution + "

";

if(description) 
{
 script_id(23938);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2007-11-04 00:32:20 +0100 (Sun, 04 Nov 2007)");
 script_cve_id("CVE-1999-0508");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");


 name = "Cisco default password";

 script_name(name);



 script_description(desc);

 summary = "Checks for a default password";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);


 script_copyright("This script is Copyright (C) 2001 - 2006 Javier Fernandez-Sanguino and Renaud Deraison");

 family = "CISCO";

 script_family(family);
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/telnet", 23);

 script_add_preference(name:"Use complete password list (not only vendor specific passwords)", type:"checkbox", value: "no");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include('default_account.inc');
include('telnet_func.inc');
include('global_settings.inc');
include("default_credentials.inc");

if ( supplied_logins_only ) exit(0);

# Function to connect to a Cisco system through telnet, send
# a password

function check_cisco_telnet(login, password, port)
{
 soc = open_sock_tcp(port);
 if ( ! soc )
 	{
	  telnet_port = 0;
	  return;
	}
 msg = telnet_negotiate(socket:soc, pattern:"(ogin:|asscode:|assword:)");

 if(strlen(msg))
 {
  # The Cisco device might be using an AAA access model
  # or have configured users:
  if ( stridx(msg, "sername:") != -1 || stridx(msg, "ogin:") != -1  )  {
    send(socket:soc, data:string(login, "\r\n"));
    msg=recv_until(socket:soc, pattern:"(assword:|asscode:)");
  }

  # Device can answer back with {P,p}assword or {P,p}asscode
  # if we don't get it then fail and close
  if ( stridx(msg, "assword:") == -1 && stridx(msg, "asscode:") == -1  )  {
    close(soc);
    return(0);
  }

  send(socket:soc, data:string(password, "\r\n"));
  r = recv(socket:soc, length:4096);

  # TODO: could check for Cisco's prompt here, it is typically
  # the device name followed by '>'  
  # But the actual regexp is quite complex, from Net-Telnet-Cisco:
  #  '/(?m:^[\r\b]?[\w.-]+\s?(?:\(config[^\)]*\))?\s?[\$\#>]\s?(?:\(enable\))?\s*$)/')
  
  # Send a 'show ver', most users (regardless of privilege level)
  # should be able to do this
  send(socket:soc, data:string("show ver\r\n"));
  r = recv_until(socket:soc, pattern:"(Cisco (Internetwork Operating System|IOS) Software|assword:|asscode:|ogin:|% Bad password)");

  # TODO: This is probably not generic enough. Some Cisco devices don't 
  # use IOS but CatOS for example

  # TODO: It might want to change the report so it tells which user / passwords
  # have been found
  if("Cisco Internetwork Operating System Software" >< r ||
     "Cisco IOS Software" >< r) 
	{
	  desc += '\n\nPlugin Output :\n\nIt was possible to log in as \'' + login + '\'/\'' + password + '\'\n';
	  security_warning(port:port, data:desc);
	  exit(0);
	}

# TODO: it could also try 'enable' here and see if it's capable
# of accessing the priviledge mode with the same password, or do it
# in a separate module

  close(soc);

 }
}

# Functions modified from the code available from default_accounts.inc
# (which is biased to UNIX)
function check_cisco_account(login, password)
{
 local_var port, ret, banner, soc, res;


 if ( ssh_port && get_port_state(ssh_port))
 { 
  # Prefer login thru SSH rather than telnet
   soc = open_sock_tcp(ssh_port);
   if ( soc )
   {
   ret = ssh_login(socket:soc, login:login, password:password);
   if ( ret == 0 ) {
        r = ssh_cmd(socket:soc, cmd: string("show ver\r\n"), timeout:60);
	if("Cisco Internetwork Operating System Software" >< r || "Cisco IOS Software" >< r) {
  	  desc += '\n\nPlugin Output :\n\nIt was possible to log in as \'' + login + '\'/\'' + password + '\'\n';
	  security_warning(port:ssh_port, data:desc);
	  close(soc);
	  exit(0);
	}  
   }
   else {
     close(soc);
     return 0;
   }   
  }
   else
     ssh_port = 0;
 }


 if(telnet_port && get_port_state(telnet_port))
 {
  if ( isnull(password) ) password = "";
  if ( ! telnet_checked ) 
  {
  banner = get_telnet_banner(port:telnet_port);
  if ( banner == NULL ) { telnet_port = 0 ; return 0; }
  # Check for banner, covers the case of Cisco telnet as well as the case
  # of a console server to a Cisco port
  # Note: banners of cisco systems are not necesarily set, so this
  # might lead to false negatives !
  if ( stridx(banner,"User Access Verification") == -1 && stridx(banner,"assword:") == -1)  
    {
     telnet_port = 0;
     return(0);
    }
   telnet_checked ++;
  }
  
  check_cisco_telnet(login:login, password:password, port:telnet_port);
 }
 return(0);
}


# SSH disabled for now
ssh_port = get_kb_item("Services/ssh");
if ( ! ssh_port ) ssh_port = 22;


telnet_port = get_kb_item("Services/telnet");
if ( ! telnet_port ) telnet_port = 23;

telnet_checked = 0;

check_cisco_account(login:"cisco", password:"cisco");
check_cisco_account(login:"", password:"");

p = script_get_preference("Use complete password list (not only vendor specific passwords)");

if("yes" >< p) {
  clist = try();
} else {
  clist = try(vendor:"cisco"); # get all cisco relevant credentials
}

if ( safe_checks() == 0 )
{
 foreach credential (clist) { 

   user_pass = split(credential, sep:";",keep:FALSE);
   if(isnull(user_pass[0]) || isnull(user_pass[1]))continue;

   user = chomp(user_pass[0]);
   pass = chomp(user_pass[1]);

   if(tolower(pass) == "none")pass = "";

   check_cisco_account(login:user, password:pass);

 }  
}

