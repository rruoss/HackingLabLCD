###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asterisk_sip_sdp_dos_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Asterisk T.38 Negotiation Remote Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Upgrade to version 1.6.0.22, 1.6.1.14, 1.6.2.2 or apply the patch,
  http://www.asterisk.org/downloads
  http://downloads.asterisk.org/pub/security/AST-2010-001-1.6.0.diff
  http://downloads.asterisk.org/pub/security/AST-2010-001-1.6.1.diff
  http://downloads.asterisk.org/pub/security/AST-2010-001-1.6.2.diff

  *****
  NOTE: Please ignore the warning if the patch is applied.
  *****";

tag_impact = "Successful exploitation could result in denial of serivce condition.
  Impact Level: Application";
tag_affected = "Asterisk version 1.6.0.x before 1.6.0.22, 1.6.1.x before 1.6.1.14, and
  1.6.2.x before 1.6.2.2";
tag_insight = "The flaw is caused by an error when handling 'T.38 negotiations' over SIP with
  a negative or overly large value in the 'FaxMaxDatagram' field, or without any
  'FaxMaxDatagram' field, which could allows attackers to crash a server.";
tag_summary = "This host is running Asterisk and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_id(800463);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-0441");
  script_bugtraq_id(38047);
  script_name("Asterisk T.38 Negotiation Remote Denial Of Service Vulnerability");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/38395");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0289");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Feb/1023532.html");
  script_xref(name : "URL" , value : "http://downloads.asterisk.org/pub/security/AST-2010-001.html");

  script_description(desc);
  script_summary("Check for the version of Asterisk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_require_keys("Asterisk-PBX/Ver", "Asterisk-PBX/Installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

asteriskVer = get_kb_item("Asterisk-PBX/Ver");
if(!asteriskVer)
{
  if(get_kb_item("Asterisk-PBX/Installed"))
  {
    astk_sock = ssh_login_or_reuse_connection();
    if(!astk_sock){
      exit(0);
    }
    paths = find_file(file_name:"asterisk", file_path:"/", useregex:TRUE,
                      regexpar:"$", sock:astk_sock);
    foreach binName (paths)
    {
      asteriskVer = get_bin_version(full_prog_name:chomp(binName), sock:astk_sock,
                                    version_argv:"-V",
                                    ver_pattern:"Asterisk ([0-9.]+(.?[a-z0-9]+)?)");
      asteriskVer[1] = ereg_replace(pattern:"-", replace:".", string:asteriskVer[1]);
      if(asteriskVer[1] != NULL)
        asteriskVer = asteriskVer[1];
    }
    ssh_close_connection();
  }
}

if(version_in_range(version:asteriskVer, test_version:"1.6.2", test_version2:"1.6.2.1")||
   version_in_range(version:asteriskVer, test_version:"1.6.0", test_version2:"1.6.0.21")||
   version_in_range(version:asteriskVer, test_version:"1.6.1", test_version2:"1.6.1.13")){
  security_warning(port:5060, proto:"udp");
}