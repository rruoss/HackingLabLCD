###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libcloud_ssl_cert_sec_bypass_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Libcloud SSL Certificates Security Bypass Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to spoof certificates and
  bypass intended access restrictions via a man-in-the-middle (MITM) attack.
  Impact Level: Application";
tag_affected = "libcloud version prior to 0.4.1";
tag_insight = "The flaw is due to improper verification of SSL certificates for
  HTTPS connections.";
tag_solution = "Upgrade to  libcloud version 0.4.1 or later
  For updates refer to http://libcloud.apache.org/";
tag_summary = "This host is installed with Libcloud and is prone to security
  bypass vulnerability.";

if(description)
{
  script_id(802164);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_cve_id("CVE-2010-4340");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Libcloud SSL Certificates Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://wiki.apache.org/incubator/LibcloudSSL");
  script_xref(name : "URL" , value : "https://issues.apache.org/jira/browse/LIBCLOUD-55");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=598463");

  script_description(desc);
  script_summary("Check for the version of Libcloud");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Confirm Linux, as SSH can be installed on Windows as well
result = ssh_cmd(socket:sock, cmd:"uname");
if("Linux" >!< result){
  exit(0);
}

## Get the file location
libName = find_file(file_name:"__init__.py", file_path:"/libcloud/", 
                            useregex:TRUE, regexpar:"$", sock:sock);

## Check for the each path
if(libName)
{
  foreach binaryName (libName)
  {
    ## Get the version
    libVer = get_bin_version(full_prog_name:"cat", sock:sock,
                             version_argv:chomp(binaryName),
                             ver_pattern:"= '([0-9.]+)'");
    if(libVer[1])
    {
      ## Check the version
      if(version_is_less(version:libVer[1], test_version:"0.4.1"))
      {
        security_warning(0);
        exit(0);
      }
    }
  }
}
