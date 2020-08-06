##############################################################################################################################
## Description      : Inspect the http headers from the given URL and extract the required data and store it in a JASON file
##############################################################################################################################
## Author           : Navneeth S Holla
##############################################################################################################################
## Date of creation : 01/08/2020
##############################################################################################################################


import requests
import json
from urllib.parse import urlparse
import time
import concurrent.futures
import yaml
from Inspect_Header_class import Inspect_Headers


'''function to inspect headers and extact the required data'''

def get_data(url,flag):
    download = requests.get(url)
    hdrs = download.headers
    inspect=Inspect_Headers()
    data = dict()
    data[url]=dict()
    with open('template.json') as f:  
        data[url]=json.load(f)

    inspect.set_cookie(hdrs,data[url]["Set-Cookie"])
    inspect.ACAO(hdrs,data[url]["Access-control-allow-origin"])
    inspect.XCTO(hdrs,data[url]["X-Content-Type-Options"]) 
    inspect.hsts(hdrs,data[url]["Strict-Transport-Security"])
    inspect.https(url,data[url]["HTTPS"])
    inspect.XXP(hdrs,data[url]["X-Xss-Protection"])
    
    if flag==1:
        with open('Hdr_data.json','a+') as f1:
            json.dump(data,f1,indent=2)
    else:
        with open('Hdr_data.json','w') as f1:
            json.dump(data,f1,indent=2)


'''function to check if the url has the required scheme'''

def check_url(url):
    url_checked = urlparse(url)
    if ((url_checked.scheme != 'http') & (url_checked.scheme != 'https')) | (url_checked.netloc == ''):
        return 0
    else: 
        return 1


def main():
    flag = 0
    #start = time.perf_counter()
    try:
        f = open('url_list.yml','r')
    except FileExistsError:
        print('Sorry. This file does not exist')
    else:
        f.close()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            result=[]
            with open('url_list.yml') as f:
                doc=yaml.full_load(f)
                for url in doc['URL']:
                    if(check_url(url)):
                        t1 = executor.submit(get_data,url,flag)
                        flag=1
                        result.append(t1)
    #stop = time.perf_counter()
    #print(stop-start)

if __name__ == "__main__":
    main()


######################################################EOF#####################################################################