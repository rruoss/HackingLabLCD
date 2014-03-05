###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_http_iis_webdav_vuln.nasl 10 2013-10-27 10:03:59Z jan $
#
# Wrapper for Nmap IIS WebDAV Vulnerability
#
# Authors:
# NSE-Script: Ron Bowes and Andrew Orr
# NASL-Wrapper: Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# NSE-Script: Copyright (c) The Nmap Security Scanner (http://nmap.org)
# NASL-Wrapper: Copyright (c) 2010 Greenbone Networks GmbH (http://www.greenbone.net)
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
tag_summary = "This script attempts to check for IIS 5.1 and 6.0 WebDAV
  Authentication Bypass Vulnerability. The vulnerability was patched
  by Microsoft MS09-020 Security patch update.

  This is a wrapper on the Nmap Security Scanner's (http://nmap.org) http-iis-webdav-vuln.nse";


if(description)
{
  script_id(801254);
  script_version("$Revision: 10 $");
  script_version("$Revision: 10 $");
  script_cve_id("CVE-2009-1122", "CVE-2009-1535");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:03:59 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2010-08-10 12:08:05 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Nmap NSE: IIS WebDAV Vulnerability");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Check for vulnerable IIS WebDAV folders");
  script_category(ACT_ATTACK);
  script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_family("Nmap NSE");
  script_add_preference(name: "Base Folder :", value: "",type: "entry");
  script_add_preference(name: "Folder db :", value: "",type: "entry");
  script_add_preference(name: "Webdav Folder :", value: "",type: "entry");
  script_add_preference(name: "http-max-cache-size :", value: "",type: "entry");
  script_add_preference(name: "http.useragent :", value: "",type: "entry");
  script_add_preference(name: "pipeline :", value: "",type: "entry");

  if(defined_func("script_mandatory_keys"))
  {
    script_mandatory_keys("Tools/Present/nmap");
    script_mandatory_keys("Tools/Launch/nmap_nse");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  }
  else
  {
    script_require_keys("Tools/Present/nmap");
    script_require_keys("Tools/Launch/nmap_nse");
  }
  exit(0);
}


include ("http_func.inc");

## Check for Required Keys
if((! get_kb_item("Tools/Present/nmap5.21") &&
   ! get_kb_item("Tools/Present/nmap5.51")) ||
   ! get_kb_item("Tools/Launch/nmap_nse")) {
 exit(0);
}

## Get HTTP Ports
port = get_http_port(default:80);
if(!port){
  exit(0);
}

argv = make_list("nmap", "--script=http-iis-webdav-vuln", "-p", port,
                  get_host_ip());

## Get the preferences
i = 0;
if( pref = script_get_preference("Base Folder :")){
  args[i++] = "basefolder="+pref;
}

if( pref = script_get_preference("Folder db :")){
  args[i++] = "folderdb="+pref;
}

if( pref = script_get_preference("Webdav Folder :")){
  args[i++] = "webdavfolder="+pref;
}

if( pref = script_get_preference("http-max-cache-size :")){
  args[i++] = "http-max-cache-size="+pref;
}

if( pref = script_get_preference("http.useragent :")){
  args[i++] = "http.useragent="+pref;
}

if( pref = script_get_preference("pipeline :")){
  args[i++] = "pipeline="+pref;
}

if (i>0)
{
  scriptArgs= "--script-args=";
  foreach arg(args) {
    scriptArgs += arg + ",";
  }
  argv = make_list(argv,scriptArgs);
}

## Run nmap and Get the result
res = pread(cmd: "nmap", argv: argv);

if(res)
{
  if("ERROR: This web server is not supported" >< res)exit(0);

  foreach line (split(res))
  {
    result = eregmatch(string:line, pattern:"http-iis-webdav-vuln: (.*)$");
    if (result) {
      msg = string('Result found by Nmap Security Scanner(http-iis-webdav-vuln.nse) ',
                   'http://nmap.org:\n', result[1]);
      security_note(data : msg, port:port);
    }
    result = eregmatch(string:line, pattern:"^nmap: (.*)$");
    if (result) {
      msg = string('Nmap command failed with following error message:\n', line);
      log_message(data : msg, port:port);
    }
  }
}
else
{
  msg = string('Following Nmap command failed entirely:\n', args);
  log_message(data : msg, port:port);
}
