#
# This script was written by Tarik El-Yassem <te@itsec.nl>
#
# Copyright (c) 2006 ITsec Security Services BV, http://www.itsec-ss.nl
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#

include("revisions-lib.inc");
tag_summary = "This plugins shows what information can be pulled of an LDAP server";

if(description)
{
  script_id(91984);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2006-04-23 14:49:44 +0200 (Sun, 23 Apr 2006)");
  name= "LDAPsearch";
  script_name(name);
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");

  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  summary = "LDAP information extraction with ldapsearch";
  script_summary(summary);

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2006 Tarik El-Yassem/ITsec Security Services");
  script_family("Remote file access");
  script_dependencies("toolcheck.nasl", "find_service.nasl", "doublecheck_std_services.nasl", "external_svc_ident.nasl","ldap_null_base.nasl","ldap_null_bind.nasl");
  script_require_ports("Services/ldap", 389);

  script_add_preference(name:"Timeout value", type:"entry", value:"3");
  script_add_preference(name:"Buffersize", type:"entry", value:"500");
  if(defined_func("script_mandatory_keys"))
    script_mandatory_keys("Tools/Present/ldapsearch");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

# script_mandatory_keys compatibility:
include ("toolcheck.inc");
exit_if_not_found (toolname: "ldapsearch");
# end of script_mandatory_keys compatibility

port = get_kb_item("Services/ldap");
if (! port) port = 389;
if (! get_port_state(port)) exit(0);

if(! null_base = get_kb_item(string("LDAP/", port, "/NULL_BASE")) && 
   ! null_bind = get_kb_item(string("LDAP/", port, "/NULL_BIND"))) {
     exit(0);
}

if (! find_in_path("ldapsearch"))
{
  log_message(port:port, data: 'Command "ldapsearch" not available to scan server (not in search path).\nTherefore this test was not executed.');
  exit(0);
}

timeout = script_get_preference("Timeout value");
buffer = script_get_preference("Buffersize");

function scanopts(ports, type, value)
{
  i = 0;
  argv[i++] = "ldapsearch";
  argv[i++] = "-h";
  argv[i++] = get_host_ip();
  argv[i++] = "-p";
  argv[i++] = port;
  argv[i++] = "-x"; #do not authenticate
  argv[i++] = "-C"; #we like to chase referals
  argv[i++] = "-b";
  argv[i++] = value;
  argv[i++] = "-s";
  argv[i++] = "base";

  if(type=="null-bind")
  {
    argv[i++] = "objectclass=*";
    argv[i++] = "-P3";
  }

  return(argv);
}


function getdc(res)
{
  #split string into array of smaller strings on each comma.
  r = split(res, sep:",");
  n = 0; 
  i = 0;
  patt = '*dc=([a-zA-Z0-9]*+)'; 
  dc = eregmatch(string:r, pattern:patt, icase:1);
  if(dc) { 
    value[i]=dc[n+1];
    #get the first value of DC=... or dc=... and put it into our array for storage
    i++;
    n++;

    foreach line (r)
    {
      if(dc[0]) {
        r = ereg_replace(string:r, pattern: dc[0], replace:'XXXXX',icase:1);
        #now replace the value we have already with some X-es so we won't find them again.    

        dc = eregmatch(string:r, pattern:patt, icase:1);
        value[i]=dc[n];
        #get the next value of dc=... or DC=...
        i++;
        if (!dc[n]) exit(0);
        n++;
     }
    }
  } 
  if (!value) exit(0);
  return(value);
}


function makereport(res, buffer, port, type)
{
  if(! res) exit(0);
  results = substr(res, 0, buffer-1);
  if (results)
  {
    s = '';

    foreach x (args) s = s + x + ' ';
    result = string("(Command was:'",  s  ,"')\n\n",results,"\n");
    return result;

  }
}

function res_check(res)
{
  if(res =~ "(S|s)uccess" && "LDAPv" >< res){
    return res;
  }
  else return(0);
}

if(!null_base)exit(0);

#first do ldapsearch -h x.x.x.x -b '' -x -C -s base
type = "null-base";
value = '';
args = scanopts(port,type,value);

res = pread(cmd:"ldapsearch", argv: args, nice: 5);
res = res_check(res);
#this is insecure, but there's no other way to do this at the moment.
if(res){
base_report = makereport(res, type);
}

if(null_bind && res) {
  #then ldapsearch -h x.x.x.x -b dc=X,dc=Y -x -C -s base 'objectclass=*' -P3 -A
  type = "null-bind"; 
  val = getdc(res); #this gets the dc values so we can use them for a ldapsearch down the branch..
  value = "dc=" + val[0] + "dc=" + val[1]; #get the first two dc values to pass it to LDAPsearch.
  #note that for deeper searches we would want use the other values in the array.
  #we could make this recursive so a user can specify how many branches we want to examine. 
  #but then we would need to grab other things like the cn values and use those in the requests.

  args = scanopts(port,type,value);

  res = pread(cmd:"ldapsearch", argv: args, nice: 5);
  res = res_check(res);
  #this is insecure, but unfortunately there's no other way to do this at the moment.
  if(res){
    bind_report =  makereport(res, type);
  }
}

if(bind_report || base_report) {

  data = string("Grabbed the following information with a null-bind, null-base request:\n");

  if(bind_report == base_report) {
   data += bind_report;
  } else {
   data += bind_report + base_report;
  }

  security_note(port:port,data:data);
  exit(0);

}

exit(0);
