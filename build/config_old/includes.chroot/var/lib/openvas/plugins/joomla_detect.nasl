###############################################################################
# OpenVAS Vulnerability Test
# $Id: joomla_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# joomla Version Detection
#
# Authors:
# Angelo Compagnucci
#
# Copyright:
# Copyright (c) 2009 Angelo Compagnucci
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100330";

if (description)
{
  script_version("$Revision: 43 $");
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-10-30 14:42:19 +0100 (Fri, 30 Oct 2009)");
  script_tag(name:"detection", value:"remote probe");
  script_name("joomla Version Detection");

  tag_summary =
"Detection of installed version of joomla

This script sends HTTP GET request and try to get the version from the
responce, and sets the result in KB.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Checks for the presence of Joomla!");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Angelo Compagnucci");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dirs = make_list("", "/cms", "/joomla", cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/index.php");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( buf == NULL )continue;

  if(egrep(pattern: '.*content="joomla.*', string: buf) ||
     egrep(pattern: '.*content="Joomla.*', string: buf) ||
     egrep(pattern: '.*href="/administrator/templates.*', string: buf) ||
     egrep(pattern: '.*src="/media/system/js.*', string: buf) ||
     egrep(pattern: '.*src="/templates/system.*', string: buf))
  {
    if(strlen(dir)>0){
      install=dir;
    } else {
        install=string("/");
    }

  }
  else
  {
    url = string(dir, "/.htaccess");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if( buf == NULL )continue;

    if(egrep(pattern: ".*# @package Joomla.*", string: buf))
    {
      if(strlen(dir)>0) {
        install=dir;
      } else {
          install=string("/");
      }
    }
    else
    {
      url = string(dir, "/templates/system/css/editor.css");
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      if( buf == NULL )continue;

      if(egrep(pattern: ".*JOOMLA.*", string: buf))
      {
        if(strlen(dir)>0) {
          install=dir;
        } else {
            install=string("/");
        }
      }
      else
      {
        url = string(dir, "/includes/js/mambojavascript.js");
        req = http_get(item:url, port:port);
        buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
        if( buf == NULL )continue;

        if(egrep(pattern: ".*@package Joomla.*", string: buf))
        {
          if(strlen(dir)>0) {
              install=dir;
          } else {
              install=string("/");	
          }
        }
      }
    }
  }

  if(install)
  {
    vers = string("unknown");
    lang = string("en-GB");

    url = string(dir, "/administrator/");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    language = eregmatch(string: buf, pattern: 'lang="(..-..)"');
    if(!isnull(language[1])) {
      lang = substr(language[1],0,1) + "-" + toupper(substr(language[1],3));
    }

    url = string(dir, "/administrator/language/"+lang+"/"+lang+".xml");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    version = eregmatch(string: buf, pattern: ".*<version>(.*)</version>.*");
    if(!isnull(version[1])) {
      vers=version[1];
    }
    else
    {
      url = string(dir, "/");
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      language = eregmatch(string: buf, pattern: 'lang="(..-..)"');
      if ( !isnull(language[1]) ) {
          lang = substr(language[1],0,1) + "-" + toupper(substr(language[1],3));
      }

      url = string(dir, "/language/"+lang+"/"+lang+".xml");
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      version = eregmatch(string: buf, pattern: ".*<version>(.*)</version>.*");
      if ( !isnull(version[1]) ) {
          vers=version[1];
      }
      else
      {
        url = string(dir, "/components/com_user/user.xml");
        req = http_get(item:url, port:port);
        buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
        version = eregmatch(string: buf, pattern: ".*<version>(.*)</version>.*");

        if ( !isnull(version[1]) ) {
            vers=version[1];
        }
        else
        {
          url = string(dir, "/modules/mod_login/mod_login.xml");
          req = http_get(item:url, port:port);
          buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
          version = eregmatch(string: buf, pattern: ".*<version>(.*)</version>.*");

          if ( !isnull(version[1]) ) {
              vers=version[1];
           }
        }
      }
    }

    tmp_version = string(vers," under ",install);
    set_kb_item(name: string("www/", port, "/joomla"), value: tmp_version);
    set_kb_item(name:"joomla/installed",value:TRUE);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:vers, exp:"([0-9.]+)", base:"cpe:/a:joomla:joomla:");
    if(isnull(cpe))
      cpe = 'cpe:/a:joomla:joomla';

    register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app:"Joomla", version:vers, install:install, cpe:cpe, concluded: version[1]),
                port:port);

    exit(0);
  }
}
exit(0);
