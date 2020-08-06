##############################################################################################################################
## Description      : Inspect the http headers from the given URL and extract the required data and store it in a JASON file
##############################################################################################################################
## Author           : Navneeth S Holla
##############################################################################################################################
## Date of creation : 01/08/2020
##############################################################################################################################


class Inspect_Headers:

    def __init__(self):
       pass

    ''' Check if the HTTP protocol has an SSL certificate  '''

    def https(self,url,required):
        if "https" in url:
            for values in required:
                values["Present"]=1


    '''Check if Set-Cookie has the required attributes'''

    def set_cookie(self,headers,required):
        for values in required:
            if "Set-Cookie" in headers:
                values["Present"]=1
                key="Set-Cookie"
                if "secure" in headers[key].lower():
                    values["Secure"]=1
                if "httponly" in headers[key].lower():
                    values["Httponly"]=1


    ''' Check if HSTS has the required attributes '''

    def hsts(self,headers,required):
        for values in required:
            if "Strict-Transport-Security" in headers:
                values["Present"]=1
                key = "Strict-Transport-Security"
                if "max-age" in headers[key].lower():
                    st=headers[key].split(';')
                    values["Max-age"]=int(st[0].strip("max-age="))


    ''' Check if X-Content-Type-Options has the required attributes '''

    def XCTO(self,headers,required):
        for values in required:
            if "X-Content-Type-Options" in headers:
                values["Present"]=1
                key="X-Content-Type-Options"
                if "nosniff" in headers[key]:
                    values["nosniff"]=1


    ''' Check if Access-control-allow-origin has the required attributes '''

    def ACAO(self,headers,required):
        for values in required:
            if "Access-control-allow-origin" in headers:
                values["Present"]=1
                key="Access-control-allow-origin"
                if '*' in headers[key]:
                    values["Star"]=1
                if 'null' in headers[key].lower():
                    values['Null']=1

    
    ''' Check if X-Xss-Protection has the required attributes '''
    
    def XXP(self,headers,required):
        for values in required:
            if "X-Xss-Protection" in headers:
                values["Present"]=1
                key="X-Xss-Protection"
                st=headers[key].split(';')
                values['Status']=int(st[0])


##########################################################EOF#################################################################