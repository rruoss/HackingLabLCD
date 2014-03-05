###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_smb_signing_disabled.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft SMB Signing Disabled
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Checking for SMB signing is disabled.

The script logs in via smb, checks the SMB Negotiate Protocol response to
confirm SMB signing is disabled.";

if(description)
{
  script_id(802726);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-09 18:56:54 +0530 (Mon, 09 Apr 2012)");
  script_name("Microsoft SMB Signing Disabled");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Check if SMB signing is disabled");
  script_category(ACT_GATHER_INFO);
  script_dependencies("smb_login.nasl");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Windows");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");

## Variable Initialization
name = "";
port = "";
soc = "";
response = "";
prot = "";

## Get name and port
name = kb_smb_name();
port = kb_smb_transport();

## Open the socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

response = smb_session_request(soc:soc, remote:name);
if(!response)
{
  close(soc);
  exit(0);
}

## SMB Negotiate Protocol Response
## If SMB signing is disabled, then Security Mode: 0x03
prot = smb_neg_prot(soc:soc);
close(soc);

if(prot && ord(prot[39]) == 3){
   log_message(data:"SMB signing is disabled on this host");
}
