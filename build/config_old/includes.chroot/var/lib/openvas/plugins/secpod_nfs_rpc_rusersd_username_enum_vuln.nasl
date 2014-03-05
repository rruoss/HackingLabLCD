###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nfs_rpc_rusersd_username_enum_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Nfs-utils 'rusersd' User Enumeration Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod
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
tag_solution = "No solution or patch is available as of 31th August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/nfs/files/nfs-utils/

  workaround:
  Disable rusers service.";

tag_impact = "Successful exploitation could allow attackers to extract the list of users
  currently logged in.
  Impact Level: System/Application";
tag_affected = "nfs-utils rpc version 1.2.3 prior.";
tag_insight = "The flaw is due to an error in remote rusers server which allows to
  extract the list of users currently logged in the remote host.";
tag_summary = "The host is running RPC rusersd service and is prone to user name
  enumeration vulnerability.";

if(description)
{
  script_id(902473);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-31 13:40:07 +0200 (Wed, 31 Aug 2011)");
  script_cve_id("CVE-1999-0626");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_name("Nfs-utils 'rusersd' User Enumeration Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


  script_description(desc);
  script_copyright("Copyright (c) 2011 SecPod");
  script_summary("Check the presence of a RPC service");
  script_category(ACT_ATTACK);
  script_family("RPC");
  script_dependencies("secpod_rpc_portmap.nasl");
  script_require_keys("rpc/portmap");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0626");
  script_xref(name : "URL" , value : "http://www.securityspace.com/smysecure/catid.html?ctype=cve&amp;id=CVE-1999-0626");
  exit(0);
}


include("misc_func.inc");

port = get_rpc_port(program:100002, protocol:IPPROTO_UDP);
if(!port){
  exit(0);
}

## Open the socket
soc = open_sock_udp(port);
req = raw_string(0x25, 0xC8, 0x20, 0x4C, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                 0x00, 0x01, 0x86, 0xA2, 0x00, 0x00,
                 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00);

send(socket:soc, data:req);

## Check for the response
resp = recv(socket:soc, length:4096);
close(soc);

if(strlen(resp) > 28)
{
  ## Check for the number of users
  nenty = ord(resp[27]);
  if(nenty == 0){
    exit(0);
  }

  start = 32;

  ## get the name of each user
  for(i=0; i < nenty ; i = i + 1)
  {
    timtl = "";
    len = 0;
    for(j = start ; ord(resp[j]) && len < 16 ; j = j + 1)
    {
      if(j > strlen(resp)){
        exit(0);
      }

      timtl = string(timtl, resp[j]);
      len = len + 1;
    }

    start = start + 12;
    user = "";
    len = 0;
    for(j = start ; ord(resp[j]) &&  len < 16; j = j + 1)
    {
      if(j > strlen(resp)){
        exit(0);
      }

      user = string(user, resp[j]);
      len = len + 1;
    }

    start = start + 12;
    usrFrom = "";
    len  = 0;
    for(j = start ; ord(resp[j]) && len < 16 ; j = j + 1)
    {
      len = len + 1;
      if(j > strlen(resp)){
        exit(0);
      }
      usrFrom = string(usrFrom, resp[j]);
    }

    start = start + 28;

    ## Check for the list of user
    if(strlen(usrFrom))
    {
      log_message(port:port);
      exit(0);
    }
  }
}
