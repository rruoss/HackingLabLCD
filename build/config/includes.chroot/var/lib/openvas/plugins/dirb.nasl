# OpenVAS Vulnerability Test
# Description: Scans the content of a web application with DIRB.  
#
# Authors:
# Christian Kuersteiner <ckuerste@gmx.ch>
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
#

include("revisions-lib.inc");
tag_summary = "This script uses DIRB to find directories and files on web
          applications via brute forcing.";

if(description)
{
  script_id(103079);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-18 13:01:55 +0100 (Fri, 18 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("DIRB (NASL wrapper)");

  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Brute force web app directories/files");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  family = "Web application abuses";
  script_family(family);
 
  script_add_preference(name: "Seed URL", type: "entry", value: "");
  script_dependencies("find_service.nasl", "httpver.nasl", "http_login.nasl");
  script_require_ports("Services/www", 80);

  script_timeout(0);

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

#
# The actual code starts here
#
include("wordlist.inc");

dirb = "dirb";

if (  !find_in_path(dirb)  )
{
  text = 'DIRB could not be found in your system path.\n';
  text += 'OpenVAS was unable to execute DIRB and to perform the scan you
requested.\nPlease make sure that DIRB is installed and is
available in the PATH variable defined for your environment.';
  log_message(port: port, data: text);
  exit(0);
}

port = get_kb_item("Services/www");
if (! port)
  port = 80;
if (! get_port_state(port))
  exit(0);

function on_exit()
{
  if (file_stat(wordlist_file))
    unlink(wordlist_file);
  if (file_stat(extension_file))
    unlink(extension_file);
}

encaps = get_port_transport(port);
if (encaps > 1)
  httprefix="https://";
else
  httprefix="http://";

httpver = get_kb_item("http/"+port);
if (httpver == "11")
  httparg=get_host_name();
else
  httparg=get_host_ip();

seed = script_get_preference ("Seed URL");
if (!seed)
  httpurl=httprefix+httparg+":"+port;
else
  httpurl=httprefix+httparg+":"+port+seed;

i = 0;
argv[i++] = dirb;

# base url
argv[i++] = httpurl;

# use wordlist from wordlist.inc
wordlist_file = get_tmp_dir() + "openvas_dirb_wordlist-" + rand() + '-' + get_host_ip() + '-' + port;
fwrite(data:wordlist_small, file:wordlist_file);

argv[i++] = wordlist_file;
# extensions to search for
extension_file = get_tmp_dir() + "openvas_dirb_extension-" + rand() + '-' + get_host_ip() + '-' + port;
fwrite(data:extension_common, file:extension_file);
argv[i++] = "-x"; argv[i++] = extension_file;

# Authenticate through cookie
cookie = get_kb_item ("/tmp/http/auth/"+port);
if (cookie)
  argv[i++] = "-c"; argv[i++] = cookie;

# make it silent
argv[i++] = "-S";

# Basic HTTP authentication
user = get_kb_item("http/login");
if (user)
{
  pass = get_kb_item("http/password");
  argv[i++] = "-u"; argv[i++] = user + ':' + pass;
}

# Start the scan
r = pread (cmd: dirb, argv: argv, cd:1);
if (!r)          # error
  exit (0);

# Parse the result and just take the URL's out
regex = "https?://[a-z0-9\-\.]*";                       # URL
regex += "(\:[0-9]{2,5})?";                             # Port
regex += "(\/([a-z0-9+\$_-]\.?)+)*\/?";                 # Path

urllist = get_kb_item("Spider/urllist");

split_str = split(r, sep:" ");
foreach match (split_str)
{
  if (url = eregmatch (pattern: regex, string: match, icase: TRUE))
  {
    report = TRUE;
    entry = url[0];
    if (!ereg (pattern: entry, string: urllist))
      urllist += string (entry, " ");
  }
}

# Save the results in the KB
set_kb_item(name: "Spider/urllist", value: urllist);

message = 'This are the directories/files found with brute force:\n\n';

message += ereg_replace(string: urllist, pattern:" ", replace: '\n');

if(report) {
  log_message(port:port, data:message);
}

exit(0);
