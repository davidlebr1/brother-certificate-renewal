'''
Description: Auto renew certificate for Brother Printer. Tested for MFC-L3750CDW 
Date: March 23, 2022
Author: @davidlebr1
'''

import requests
import urllib3
import argparse
from requests_html import HTMLSession

# Remove insecure warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global Variable
protocol = "https" # http or https
hostname = "" # hostname or ip of your printer
certificate = "" # Certificate path
password = "" # Admin password login
session = HTMLSession()


def authenticate():
	# Get CSRF token from login
	response = session.get("{}://{}/general/status.html".format(protocol, hostname), verify=False)
	token = response.html.xpath('//*[@id="CSRFToken"]')[0].attrs['value']

	# Authenticate
	paramsPost = {"B129f":password,"CSRFToken":token,"loginurl":"/general/status.html"}
	response = session.post("{}://{}/general/status.html".format(protocol, hostname), data=paramsPost, verify=False)

	check_login = response.html.xpath('/html/body/div/div/div[1]/div/div/div[3]/ul/li[3]/ul/li/a')
	if check_login:
		print("[*] Login Successful")
	else:
		print("[*] Couldn't login")

def deleteCert():
	# Delete last Cert
	#Get idx cert
	idx = 0
	response = session.get("{}://{}/net/security/certificate/certificate.html".format(protocol, hostname), verify=False)
	links = response.html.links
	for link in links:
		if "view.html?idx=" in link:
			idx = link.split("=")[1]
			break

	# Get CSRF from delete page
	response = session.get("{}://{}/net/security/certificate/delete.html?idx={}".format(protocol, hostname, idx), verify=False)
	token = response.html.xpath('/html/body/div/div/div[2]/div[2]/div[2]/div/div/div[2]/form/div[2]/input')[0].attrs['value']

	# Delete cert
	paramsPost = {"hidden_certificate_process_control":"1","CSRFToken":token,"hidden_certificate_idx":idx,"B12b0":"","B12c2":"","pageid":"380"}
	response = session.post("{}://{}/net/security/certificate/delete.html".format(protocol, hostname), data=paramsPost)

	if idx != 0:
		# Check if cert was deleted
		response = session.get("{}://{}/net/security/certificate/delete.html?idx={}".format(protocol, hostname, idx), verify=False)
		is_deleted = response.html.xpath('/html/body/div/div/div[2]/div[2]/div[2]/div/div/div[2]/form/div[3]/p')
		if is_deleted:
			print("[*] The certificate has been successfully deleted")
		else:
			print("[*] The certificate has not been deleted")
	else:
		print("[*] There is no certificate to delete")

def uploadCert():
	# Upload cert
	# Get CSRF token to submit new cert
	response = session.get("{}://{}/net/security/certificate/import.html?pageid=387".format(protocol,hostname), verify=False)
	token = response.html.xpath('/html/body/div/div/div[1]/div/div/div[1]/div[1]/div/div/form/div/input[1]')[0].attrs['value']

	headers = {"Origin":"{}://{}".format(protocol, hostname),"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0","Referer":"{}://{}/net/security/certificate/import.html?pageid=387".format(protocol, hostname),"Connection":"close","Sec-Fetch-Dest":"document","Sec-Fetch-Site":"same-origin","Accept-Encoding":"gzip, deflate","Dnt":"1","Sec-Fetch-Mode":"navigate","Te":"trailers","Upgrade-Insecure-Requests":"1","Sec-Gpc":"1","Sec-Fetch-User":"?1","Accept-Language":"en-CA,en-US;q=0.7,en;q=0.3"}
	paramsPost = {"hidden_certificate_process_control":"1","CSRFToken":token,"hidden_cert_import_password":"","B12b0":"","B11b1":"","pageid":"387","B12be":""}
	#paramsMultipart = [('B11b0', ('brother.pfx', open(certificate, 'rb'), 'application/x-pkcs12'))]
	paramsMultipart = {"B11b0": open(certificate, 'rb')}
	response = session.post("{}://{}/net/security/certificate/import.html".format(protocol, hostname), data=paramsPost, files=paramsMultipart, headers=headers, allow_redirects=True, verify=False)
	error = response.html.find('div', containing='rejected')
	if error:
		print("[*] An error occured in the upload")
	else:
		print("[*] The certificate has been Successfully uploaded")

def selectCert():
	# Select certificate in HTTP Server Settings
	# Get CSRF Token
	response = session.get("{}://{}/net/net/certificate/http.html".format(protocol,hostname), verify=False)
	token = response.html.xpath('/html/body/div/div/div[2]/div[2]/div[2]/div/div/div[2]/form/div[2]/input')[0].attrs['value']

	# Get the Cert from dropdown
	cert_dropdown_id = response.html.xpath('/html/body/div/div/div[2]/div[2]/div[2]/div/div/div[2]/form/div[4]/dl[1]/dd/select/option[2]')[0].attrs['value']

	# Post the selected cert to use it
	paramsPost = {"B12c9":cert_dropdown_id,"CSRFToken":token,"B11fc":"1","B12e3":"0","pageid":"325","B12c7":"","http_page_mode":"0","B12c6":"","B120c":"1"}
	response = session.post("{}://{}/net/net/certificate/http.html".format(protocol, hostname), data=paramsPost)
	print("[*] Selected cert with id {}".format(cert_dropdown_id))


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("url", help="Hostname or IP. Without http://. ", type=str)
	parser.add_argument("certificate", help="Full path of the certificate (.pfx file).", type=str)
	parser.add_argument("password", help="Administrator login password", type=str)
	parser.add_argument("-p", "--protocol", dest="protocol", help="Protocol: HTTP or HTTPS. By default it's https ", default="https", type=str)

	args = parser.parse_args()

	protocol = args.protocol
	hostname = args.url
	password = args.password
	certificate = args.certificate

	authenticate()
	deleteCert()
	uploadCert()
	selectCert()

