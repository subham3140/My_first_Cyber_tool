import argparse

import validators

import requests

from urllib.parse  import urlparse

from bs4 import BeautifulSoup
from bs4 import Comment
import yaml


parser = argparse.ArgumentParser(description="The Achilles HTML Vulnerablity Analyze Version 1.0")

parser.add_argument('-v','--version',action='version',version='%(prog)s 1.0')

parser.add_argument('url',type=str,help="The URL of the HTML to Analyze")

parser.add_argument('--config',help='Path to congifguration file')

parser.add_argument('-o','--output',help='Report file output path')

args = parser.parse_args()

config = {'forms':True,'comments':True,'password_inputs':True}

if (args.config):
	
	config_file = open(args.config,'r')
	
	config_from_file = yaml.load(config_file,Loader=yaml.FullLoader)
	
	if (config_from_file):
		
		config = {**config , **config_from_file}
		
url = args.url


report = ''

if (validators.url(url)):
	result_html = requests.get(url).text

	parsed_html = BeautifulSoup(result_html,'html.parser')

	forms = parsed_html.find_all('form')
	
	comments = parsed_html.find_all(string=lambda text:isinstance(text,Comment))

	password_inputs = parsed_html.find_all('input', {'name':'password'})

	if (config['forms']):
		for form in forms:
			if((form.get('action').find('https') < 0) and (urlparse(url).scheme != 'https')):
		
				report += 'Form Issue:Insecure form action ' + form.get('action') + ' found in document.\n'

	if (config['comments']):
		for comment in comments:
			if(comment.find('key: ') > -1):
				report += 'Comment Issue: Key in the HTML comments,Please remove.\n'

	if (config['password_inputs']):
		for password in password_inputs:
			if(password.get('type') != 'password'):
				report += 'Input Issue:PlanText password input found.Please change the input type=password otherwise your password will be catch easily as a simple text.\n'


else:
	print("Invalid URL Please include full URL including scheme.")


if(report == ''):

    report +='Nice job! your HTML document is secure\n'
else:
	
	header ='Vulnerability Report is as follows:\n'
	
	header +='===================================\n\n'

	report = header + report

if (args.output):

	with open(args.output,'w') as f:
		f.write(report)
	print('Report saved to: '+args.output)
 















