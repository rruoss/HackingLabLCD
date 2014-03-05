###############################################################################
# OpenVAS Vulnerability Test
# $Id:gb_sun_java_sys_web_serv_info_disc_vuln.nasl 3416 2009-07-22 17:58:32Z jul $
#
# Sun Java System Web Server '.jsp' Information Disclosure Vulnerability (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will lets the attackers to execute arbitrary code,
  gain sensitive information.
  Impact Level: System/Application";
tag_affected = "Sun Java System Web Server versions 6.1 and before 6.1 SP11 and
  Sun Java System Web Server versions 7.0 update 5 on Windows.";
tag_insight = "This issue is caused by an error when handling requests to JSP files with the
  '.jsp::$DATA' string appended to the file extension, which could be exploited
  by remote attackers to display the source code of arbitrary JSP files instead
  of an expected HTML response.";
tag_solution = "No solution or patch is available as of 22nd July, 2009. Information
  regarding this issue will update once the solution details are available.
  For updates refer to http://www.sun.com/";
tag_summary = "This host is running Sun Java Web Server which is prone to Information
  Disclosure Vulnerability.";

if(description)
{
  script_id(800658);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-22 21:36:53 +0200 (Wed, 22 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2445");
  script_bugtraq_id(35577);
  script_name("Sun Java System Web Server '.jsp' Information Disclosure Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35701");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1022511");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1786");

  script_description(desc);
  script_summary("Check for the version of Java System Web Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_sun_java_sys_web_serv_detect.nasl",
                      "secpod_reg_enum.nasl");
  script_require_keys("Sun/Java/SysWebServ/Ver", "SMB/WindowsVersion");
  script_require_ports(139,445);
  script_require_ports("Services/www", 8888, 8989, 139, 445);
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

jwebVer = get_kb_item("Sun/JavaSysWebServ/Ver");
if(!jwebVer){
  exit(0);
}

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Sun Microsystems\WebServer")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

if("6.1" >< jwebVer)
{
  foreach item (registry_enum_keys(key:key))
  {
    jswsName = registry_get_sz(key:key + item, item:"DisplayName");
    if(jswsName != NULL && jswsName =~ "Sun (ONE |Java System )Web Server")
    {
      jswsVer = eregmatch(pattern:"Web Server ([0-9.]+)(SP[0-9]+)?",string:jswsName);
      if(jswsVer[1] != NULL)
      {
        if(jswsVer[2] != NULL)
         jswsVer = jswsVer[1] + "." + jswsVer[2];
        else
         jswsVer = jswsVer[1];
      }
    }
  }
}
else if("7.0" >< jwebVer)
{
  jswsPath = registry_get_sz(key:key + "Sun Java System Web Server",
                             item:"UninstallString");
  if(jswsPath != NULL)
  {
    jswsPath = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:jswsPath);
    jswsPath = jswsPath - "\bin\uninstall.exe" + "\README.TXT";

    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:jswsPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",string:jswsPath);
    jswsVer = read_file(share:share, file:file, offset:0, count:150);

    if(jswsVer != NULL)
    {
      jswsVer = eregmatch(pattern:"Web Server ([0-9.]+)([ a-zA-z]+)?([0-9]+)?",
                          string:jswsVer);
      if(jswsVer[1] != NULL)
      {
        if(jswsVer[3] != NULL)
         jswsVer = jswsVer[1] + "." + jswsVer[3];
        else
         jswsVer = jswsVer[1];
      }
    }
  }
}

if(jswsVer != NULL)
{
  # Grep for versions 6.1 <= 6.1SP11 and 7.0 <= 7.0 Updatae 5
  if(version_in_range(version:jswsVer, test_version:"6.1", test_version2:"6.1.SP11")||
    version_in_range(version:jswsVer, test_version:"7.0", test_version2:"7.0.5"))
  {
    jswsPort = get_kb_item("Sun/JavaSysWebServ/Port");
    security_warning(jswsPort);
  }
}
