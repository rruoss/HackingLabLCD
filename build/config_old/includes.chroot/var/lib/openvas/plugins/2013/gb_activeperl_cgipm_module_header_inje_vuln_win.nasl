###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_activeperl_cgipm_module_header_inje_vuln_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Active Perl CGI.pm 'Set-Cookie' and 'P3P' HTTP Header Injection Vulnerability (Win)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to inject new header items
  or modify header items.
  Impact Level: Application";

tag_affected = "Active Perl CGI.pm module before 3.63 on Windows";
tag_insight = "The 'CGI.pm' module does not properly filter carriage returns from user
  supplied input to be used in Set-Cookie and P3P headers.";
tag_solution = "Upgrade to Active Perl CGI.pm module version 3.63 or later,
  For updates refer to http://www.perl.org/get.html";
tag_summary = "The host is installed with Active Perl and is prone to HTTP header
  injection vulnerability.";

if(description)
{
  script_id(803344);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-5526");
  script_bugtraq_id(56562);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-23 18:18:09 +0530 (Wed, 23 Jan 2013)");
  script_name("Active Perl CGI.pm 'Set-Cookie' and 'P3P' HTTP Header Injection Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/87613");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80098");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1027780");
  script_xref(name : "URL" , value : "http://cpansearch.perl.org/src/MARKSTOS/CGI.pm-3.63/Changes");
  script_summary("Check for the vulnerable version of Active Perl CGI.pm module on Windows ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("ActivePerl/Ver", "ActivePerl/Loc");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
apLoc = "";
insPath = "";
txtRead = "";
perVer = "";

## Get Install Location
apLoc = get_kb_item("ActivePerl/Loc");
if(apLoc)
{
  ## append the CGI module file
  insPath =  apLoc+ "\lib\CGI.PM";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:insPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:insPath);

  ## Read the file CGI.PM
  txtRead = read_file(share:share, file:file, offset:0, count:10000);
  if("CGI::revision" >< txtRead)
  {
    ## Grep for the CGI.PM module version
    perVer = eregmatch(pattern:"CGI::VERSION='([0-9.]+)", string:txtRead);
    if(perVer[1])
    {
      if(version_is_less(version:perVer[1], test_version:"3.63"))
      {
        security_warning(0);
        exit(0);
      }
    }
  }
}
