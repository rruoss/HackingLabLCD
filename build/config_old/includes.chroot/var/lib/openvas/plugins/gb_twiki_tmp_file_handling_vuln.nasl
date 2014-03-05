###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twiki_tmp_file_handling_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Insecure tempfile handling Vulnerability in TWiki - Sep08
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful attack could lead to rewriting some system file.
  Impact Level: Application";
tag_affected = "TWiki Version 4.1.2.";
tag_insight = "Local users can overwrite arbitrary files via a symlink attack on the
  /tmp/twiki temporary file.";
tag_solution = "Upgrade TWiki to higher version.
  http://twiki.org/";
tag_summary = "The host is running TWiki which is prone to Insecure temp file
  handling Vulnerability.";

if(description)
{
  script_id(800130);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-11 09:14:20 +0100 (Tue, 11 Nov 2008)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-4998");
  script_name("Insecure tempfile handling Vulnerability in TWiki - Sep08");
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
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2008/10/30/2");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=494648");

  script_description(desc);
  script_summary("Check for the Version of TWiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

dirs = make_list("/twiki", cgi_dirs());
foreach dir (dirs)
{
  soc = http_open_socket(port);
  if(!soc){
    exit(0);
  }

  sndReq = http_get(item:dir + "/bin/view/TWiki/WebHome", port:port);
  send(socket:soc, data:sndReq);
  rcvRes = http_recv(socket:soc);

  http_close_socket(soc);

  if(rcvRes =~ "Powered by TWiki")
  {
    twikiVer = eregmatch(pattern:"TWiki-([0-9.]+),", string:rcvRes);

    if(twikiVer[1] == "4.1.2"){
      security_hole(port);
    }
    exit(0);
  }
}
