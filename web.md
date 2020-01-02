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

<h2 id="application">Application</h2>

<h3 id="open">Open Redirect</h3>

	redirect_url=http%3A%2F%2Fevil.url # http://evil.url

<b>Upgrade to Response Splitting</b>

<h3 id="csrf">Cross Site Request Forgery</h3>



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
