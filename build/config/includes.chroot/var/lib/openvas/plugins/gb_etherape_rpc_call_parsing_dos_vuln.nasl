###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_etherape_rpc_call_parsing_dos_vuln.nasl 72 2013-11-21 17:10:44Z mime $
#
# EtherApe RPC Packet Processing Denial of Service Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation allows remote attackers to cause a NULL pointer
  dereference or cause a denial of service.
  Impact Level: Application";
tag_affected = "EtherApe version prior to 0.9.12";
tag_insight = "The flaw is due to an error in the add_conversation function in
  'conversations.c' when processing specially crafted RPC packet.";
tag_solution = "Upgrade to EtherApe version 0.9.12 or later,
  For updates refer to http://etherape.sourceforge.net/";
tag_summary = "This host is installed with EtherApe and is prone to denial of
  service vulnerabilities.";

if(description)
{
  script_id(802340);
  script_version("$Revision: 72 $");
  script_cve_id("CVE-2011-3369");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-11-21 18:10:44 +0100 (Thu, 21 Nov 2013) $");
  script_tag(name:"creation_date", value:"2011-11-08 17:22:20 +0530 (Tue, 08 Nov 2011)");
  script_name("EtherApe RPC Packet Processing Denial of Service Vulnerability");
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
  script_summary("Check for the version of EtherApe");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/75609");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45989");
  script_xref(name : "URL" , value : "http://etherape.sourceforge.net/NEWS.html");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/09/19/4");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/09/22/1");
  script_xref(name : "URL" , value : "http://sourceforge.net/tracker/?func=detail&amp;aid=3309061&amp;group_id=2712&amp;atid=102712");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

## Open the socket
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Confirm Linux, as SSH can be instslled on Windows as well
result = ssh_cmd(socket:sock, cmd:"uname");
if("Linux" >!< result){
  exit(0);
}

etherapeName = find_file(file_name:"etherape", file_path:"/", useregex:TRUE,
                         regexpar:"$", sock:sock);

foreach binaryName (etherapeName)
{
  ## Get the EtherApe version from command
  etherVer = get_bin_version(full_prog_name:chomp(binaryName), version_argv:"--version",
                             ver_pattern:"GNOME EtherApe ([0-9.]+)", sock:sock);

  if(etherVer[1])
  {
    ## Check for EtherApe Version less than 0.9.12
    if(version_is_less(version:etherVer[1], test_version:"0.9.12"))
    {
      security_warning(0);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
