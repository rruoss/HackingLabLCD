# OpenVAS Vulnerability Test
# $Id: ldu_detection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Detects LDU version
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote web server contains a content management system written in
PHP. 

Description :

This script detects whether the remote host is running Land Down Under
(LDU) and extracts the version number and location if found. 

Land Down Under is a content management system using PHP and MySQL.";

if(description)
{
 script_id(19602);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 
 name = "Detects LDU version";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);
 
 summary = "LDU detection";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_xref(name : "URL" , value : "http://www.neocrome.net/");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);


foreach dir ( cgi_dirs() )
{
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it looks like LDU.
  if 
  (
    # Cookie from LDU
    "^Set-Cookie: LDUC" >< res ||
    # Meta tag (generator) from LDU
    'content="Land Down Under Copyright Neocrome' >< res || 
    # Meta tag (keywords) from LDU
    'content="LDU,land,down,under' >< res
  )
  {
    # First we'll try to grab the version from the main page
    pat = "Powered by <a [^<]+ LDU ([0-9.]+)<";
    matches = egrep(pattern:pat, string:res);
    if (matches)
    {
      foreach match (split(matches)) 
      {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) 
        {
          ver = ver[1];
          break;
        }
      }
    }

    #If unsuccessful try grabbing the version from the readme.old_documentation.htm file.
    if (isnull(ver)) 
    {
      req = http_get ( item:string (dir, "/docs/readme.old_documentation.htm"), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);
      pat = 'id="top"></a>Land Down Under v([0-9]+)<';
      matches = egrep(pattern:pat, string:res);
      if (matches)
      {
        foreach match (split(matches)) 
        {
          match = chomp(match);
          ver = eregmatch(pattern:pat, string:match);
          if (!isnull(ver)) 
          {
            ver = ver[1];
            break;
          }
        }
      }
    }

    if (isnull(ver)) ver = "unknown";

    # Generate report and update KB.
    #
    # nb: even if we don't know the version number, it's still useful
    #     to know that it's installed and where.
    if (dir == "") dir = "/";
    if (ver == "unknown")
    { 
      report = string(
        "An unknown version of Land Down Under is installed under ", dir, "\n",
        "on the remote host.");
    }
    else
    {
      report = string(
        "Land Down Under version ", ver, " is installed under ", dir, " on the\n",
        "remote host."
      );
    }
    report = string
    (
      report,
      "\n\n",
      "Land Down Under is a highly customizable and fully scalable website engine\n",
      "powered by PHP and MySQL. See http://www.neocrome.net/ for more information\n"
    );
    security_note(data:report, port:port);
    set_kb_item
    (
      name:string("www/", port, "/ldu"),
      value:string(ver, " under ", dir)
    );
  }
}
