# OpenVAS Vulnerability Test
# $Id: netbios_name_get.nasl 41 2013-11-04 19:00:12Z jan $
# Description: Using NetBIOS to retrieve information from a Windows host
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd :
# - bug fix in the adaptater conversion
# - export results in the KB
# rev 1.5 changes by ky :
# - added full support for Win2k/WinXP/Win2k3
# - added export of SMB/username KB
# rev 1.6 changes by KK :
# - added export of SMB/messenger KB
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
tag_summary = "The NetBIOS port is open (UDP:137). A remote attacker may use this to gain
access to sensitive information such as computer name, workgroup/domain
name, currently logged on user name, etc.";

tag_solution = "Block those ports from outside communication";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.10150";

if(description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "Using NetBIOS to retrieve information from a Windows host";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Using NetBIOS to retrieve information from a Windows host";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 1999 SecuriTeam");
 family = "Windows";
 script_family(family);
 script_dependencies("cifs445.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("host_details.inc");

SCRIPT_DESC = 'Using NetBIOS to retrieve information from a Windows host';

function isprint(c)
{
 min = ord("!");
 max = ord("~");
 ordc = ord(c);
 if(ordc > max)return(FALSE);
 if(ordc < min)return(FALSE);
 return(TRUE);
}

# do not test this bug locally

NETBIOS_LEN = 50;


sendata = raw_string(
rand()%255, rand()%255, 0x00, 0x00, 0x00,
0x01, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x20, 0x43, 0x4B,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x00, 0x00, 0x21, 0x00, 0x01
			);
			
#query *SMBSERVER<20> - by KK Liu 03/24/2004			
sendata_SMBSERVER = raw_string(
rand()%255, rand()%255, 0x00, 0x10, 0x00,
0x01, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x20, 0x43, 0x4b,
0x46, 0x44, 0x45, 0x4e, 0x45,
0x43, 0x46, 0x44, 0x45, 0x46,
0x46, 0x43, 0x46, 0x47, 0x45,
0x46, 0x46, 0x43, 0x43, 0x41,
0x43, 0x41, 0x43, 0x41, 0x43,
0x41, 0x43, 0x41, 0x43, 0x41,
0x00, 0x00, 0x21, 0x00, 0x01
			);

hostname_found = 0;
group_found = 0;
messenger_found = 0;
candidate = "";

if(!(get_udp_port_state(137))){
	set_kb_item(name:"SMB/name", value:get_host_ip());
	exit(0);
	}
	
dsport = 137;
soc = open_sock_udp(137);
send(socket:soc, data:sendata, length:NETBIOS_LEN);

result = recv(socket:soc, length:4096);

#query *SMBSERVER<20> - by KK Liu 03/24/2004
if (strlen(result) < 56)
{
 send(socket:soc, data:sendata_SMBSERVER, length:NETBIOS_LEN);
 result = recv(socket:soc, length:4096);
}

if (strlen(result) > 56)
{  
 hole_answer = "";

 hole_data = result;

 location = 0;
 location = location + 56;
 
 num_of_names = ord(hole_data[location]);
 if (num_of_names > 0)
 {
  hole_answer = string(hole_answer, "The following ",	num_of_names,
	" NetBIOS names have been gathered :\n");
 }

 location = location + 1;

 for (name_count = 0; name_count < num_of_names; name_count = name_count + 1)
 {
  name = "";
  for (name_copy = 0; name_copy < 15; name_copy = name_copy + 1)
  {
   loc = location+name_copy+name_count*18;
   if(isprint(c:hole_data[location+name_copy+name_count*18]))
   {
    name = string(name, hole_data[location+name_copy+name_count*18]);
   }
   else
    name = string(name, " ");
  }
  loc = location+16+name_count*18;
 
   
  # Win2k/WinXP sends 0xc4-196 and 0x44-68 as the loc name flags
  if(hole_data[loc] == raw_string(68))
  {
   subloc = location+15+name_count*18;
   if(ord(hole_data[subloc])==32)
   {
    if(!hostname_found && name)
    {
     set_kb_item(name:"SMB/name", value:name);
     hostname_found = 1;
    }
    name = name + " = This is the computer name";
   }
   else if(ord(hole_data[subloc])==0)
   {
    candidate = name;
    if(!("~" >< name))
    {
     if(!hostname_found && name)
     {
      set_kb_item(name:"SMB/name", value:name);
      hostname_found = 1;
     }
    }
   }
   # Set the current logged in user based on the last entry
   if (hole_data[subloc] == raw_string(3))
   {
    # Ugh, we can get multiple usernames with TS or Citrix
    # Also, the entry is the same for the local workstation or user name
    username = name;
    name = name + " = This is the current logged in user or registered workstation name.";
   }
        
   if(ord(hole_data[subloc]) == 27)
   {
    if(!group_found && name)
    {
     set_kb_item(name:"SMB/workgroup", value:name);
     group_found = 1;
    }
   }

   if (hole_data[subloc] == raw_string(1))
   {
    name = name + " = Computer name that is registered for the messenger service on a computer that is a WINS client.";
    messenger_found = 1;
    messenger = name;
   }
   if (hole_data[subloc] == raw_string(190))
   {
    name = name + " = A unique name that is registered when the Network Monitor agent is started on the computer";
   }
   if (hole_data[subloc] == raw_string(31))
   {
    name = name + " = A unique name that is registered for Network dynamic data exchange (DDE) when the NetDDE service is started on the computer.";
   }
   
   
  }

  # Set the workgroup info on WinXP
  if (hole_data[loc] == raw_string(196))
  {
   subloc = location+15+name_count*18;
   
   if (hole_data[subloc] == raw_string(0))  
   {
    if(!group_found && name)
    {
      set_kb_item(name:"SMB/workgroup", value:name);
      group_found = 1;
    }
    name = name + " = Workgroup / Domain name";
   }
   if (hole_data[subloc] == raw_string(30))  
   {
    name = name + " = Workgroup / Domain name (part of the Browser elections)";
   }
   if (hole_data[subloc] == raw_string(27))  
   {
    name = name + " = Workgroup / Domain name (elected Master Browser)";
   }
   if (hole_data[subloc] == raw_string(28))  
   {
    name = name + " = Workgroup / Domain name (Domain Controller)";
   }
   if (hole_data[subloc] == raw_string(191))  
   {
    name = name + " = A group name that is registered when the Network Monitor agent is started on the computer.";
   }
  }

  # WinNT sends 0x04-4 and 0x84-132 as the loc name flags
  if (hole_data[loc] == raw_string(4))
  {
   subloc = location+15+name_count*18;

   if (hole_data[subloc] == raw_string(0))
   {
    if(!hostname_found && name)
    {
     set_kb_item(name:"SMB/name", value:name);
     hostname_found = 1;
    }
    if ( "~" >!< name )name = name + " = This is the computer name registered for workstation services by a WINS client.";
   }

   # Set the current logged in user based on the last entry
   if (hole_data[subloc] == raw_string(3))
   {
   {
    # Ugh, we can get multiple usernames with TS or Citrix
    username = name;
    name = name + " = This is the current logged in user registered for this workstation.";
   }
   }

   if (hole_data[subloc] == raw_string(1))
   {
    name = name + " = Computer name that is registered for the messenger service on a computer that is a WINS client.";
    messenger_found = 1;
    messenger = name;
   }
   if (hole_data[subloc] == raw_string(190))
   {
    name = name + " = A unique name that is registered when the Network Monitor agent is started on the computer";
   }
   if (hole_data[subloc] == raw_string(31))
   {
    name = name + " = A unique name that is registered for Network dynamic data exchange (DDE) when the NetDDE service is started on the 
computer.";
   }   
   
   if (hole_data[subloc] == raw_string(32))
   {
    name = name + " = Computer name";
   }   
  }

  loc = location+16+name_count*18;

 
  
  # Set the workgroup info on WinNT  
  if (hole_data[loc] == raw_string(132))
  {
   subloc = location+15+name_count*18;
   
   if (hole_data[subloc] == raw_string(0))  
   {
    if(!group_found && name)
    {
      set_kb_item(name:"SMB/workgroup", value:name);
      group_found = 1;
    }
    name = name + " = Workgroup / Domain name";
   }
   if (hole_data[subloc] == raw_string(30))  
   {
    name = name + " = Workgroup / Domain name (part of the Browser elections)";
   }
   if (hole_data[subloc] == raw_string(27))  
   {
    name = name + " = Workgroup / Domain name (elected Master Browser)";
   }
   if (hole_data[subloc] == raw_string(28))  
   {
    name = name + " = Workgroup / Domain name (Domain Controller)";
   }
   if (hole_data[subloc] == raw_string(191))  
   {
    name = name + " = A group name that is registered when the Network Monitor agent is started on the computer.";
   }
   
  }
  

  hole_answer = hole_answer + " " + name +  string("\n");
 }

 
 location = location + num_of_names*18;

 adapter_name = "";
 for (adapter_count = 0; adapter_count < 6; adapter_count = adapter_count + 1)
 {
  loc = location + adapter_count;
  if ( adapter_count == 5 ) col = "";
  else col = ":";
  adapter_name = adapter_name + tolower(string(hex(ord(hole_data[loc])), col)) - "0x";
 }
 if(adapter_name == "00:00:00:00:00:00")
 {
   set_kb_item(name:"SMB/samba", value:TRUE);  
   hole_answer = hole_answer + string("\n. This SMB server seems to be a SAMBA server (this is not a security
risk, this is for your information). This can be told because this server 
claims to have a null MAC address");
 }
 else
 {
  hole_answer = hole_answer + string("The remote host has the following MAC address on its adapter :\n");
  hole_answer = hole_answer + "   " + adapter_name;
  register_host_detail(name:"MAC", value:adapter_name, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
 }
 hole_answer = hole_answer + string("\n\nIf you do not want to allow everyone to find the NetBios name\nof your computer, you should filter incoming traffic to this port.");
 log_message(port:137, data:hole_answer, protocol:"udp");
}
 if(!hostname_found)
     {
      if(candidate)
      {
      set_kb_item(name:"SMB/name", value:candidate);
      hostname_found = 1;
      }
      else set_kb_item(name:"SMB/name", value:get_host_ip());
     }

 if (username)
     {
	set_kb_item(name:"SMB/username", value:username);
     }

 if (messenger_found && messenger)
     {
	set_kb_item(name:"SMB/username", value:messenger);
     }

close(soc);
