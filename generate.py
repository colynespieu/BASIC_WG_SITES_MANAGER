#!/usr/bin/python3
from jinja2 import Environment, FileSystemLoader
from warnings import filterwarnings
filterwarnings("ignore")
import os,scp,subprocess,json,paramiko,io,sys,re
from getpass import getpass

global base_path, conffile, certs_path, sites_path, templates_path, export_path, sitename

base_path = os.getcwd()+"/"
conffile = base_path+"conf.json"
certs_path = base_path+"certs/"
sites_path = base_path+"sites/"
templates_path = base_path+"templates/"
exports_path = base_path+"exports/"


def get_sitename():
    with open(conffile, "r") as jsonfile:
        toreturn = json.loads(jsonfile.read())["site"]
    return(toreturn)

def pass_command_ssh(username,password,host,port,command):
    try:
        sshClient = paramiko.SSHClient()
        sshClient.load_system_host_keys()
        sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sshClient.connect(host, port=port, username=username, password=password, allow_agent=False,look_for_keys=False)
        stdin,stdout,stderr = sshClient.exec_command(command)
        toreturn = stdout.read().decode()
    finally:
        sshClient.close()
    return(toreturn)

def json_file_read(filepath):
    with open(filepath, "r") as jsonfile:
        toreturn = json.loads(jsonfile.read())
    return(toreturn)

def json_file_save(filepath,value):
    with open(filepath, "w") as jsonfile:
        json.dump(value, jsonfile,indent = 4)

def generate_wireguard_keys():
    privkey = subprocess.check_output("wg genkey", shell=True).decode("utf-8").strip()
    pubkey = subprocess.check_output(f"echo '{privkey}' | wg pubkey", shell=True).decode("utf-8").strip()
    return (privkey, pubkey)

def generate_wireguard_cert(certname):
    if not os.path.exists(f"{certs_path}{sitename}/{certname}.json"):
        privkey,pubkey = generate_wireguard_keys()
        privpubarray={"private_key":privkey,"public_key":pubkey}
        json_file_save(f"{certs_path}{sitename}/{certname}.json",privpubarray)
    else:
        print(f"Le fichier cert '{certname}' existe déja !")
        return

def delete_wireguard_cert(certname):
    if os.path.exists(f"{certs_path}{sitename}/{certname}.json"):
        os.remove(f"{certs_path}{sitename}/{certname}.json")
    else:
        print(f"Le fichier cert '{certname}' n'existe pas !")
        return

def add_wireguard_host(host):
    site_values = json_file_read(f"{sites_path}/{sitename}.json")
    maxincrement = 0
    if "used_ips" in site_values:
        for ips in site_values["used_ips"]:
            if int(maxincrement) < int(ips.split(".")[3]):
                maxincrement = ips.split(".")[3]
            if site_values["used_ips"][ips] == host:
                print(f"Le cert '{host}' existe déja !")
                return
    if site_values["subnet"].split("/")[0].replace(".","").isdigit():
        tmp_list=site_values["subnet"].split("/")[0].split(".")
        host_ip=f"{tmp_list[0]}.{tmp_list[1]}.{tmp_list[2]}.{str(int(maxincrement)+1)}"
    else:
        print(f"Le subnet '{site_values['subnet']}' n'est pas correcte !")
        return
    site_values["used_ips"][host_ip]=host
    json_file_save(f"{sites_path}/{sitename}.json",site_values)

def del_wireguard_host(host):
    site_values = json_file_read(f"{sites_path}/{sitename}.json")
    todel = ""
    if "used_ips" in site_values:
        for i in site_values["used_ips"]:
            if (site_values["used_ips"][i] == host):
                todel=i
    site_values["used_ips"].pop(todel, None)
    json_file_save(f"{sites_path}/{sitename}.json",site_values)

def deploy_wireguard_configuration_routeros(password):
    site_values = json_file_read(f"{sites_path}/{sitename}.json")
    cert_values = json_file_read(f"{certs_path}/{sitename}/{site_values['server']['name']}.json")
    username,host,port = site_values["server"]["type_info"]["ssh_user"],site_values["server"]["IP"],site_values["server"]["type_info"]["ssh_port"]
    command = "/interface/wireguard/print detail"
    interfaces_wireguard_print = pass_command_ssh(username,password,host,port,command)
    command = f"/interface/wireguard/peers/print detail where interface=\"{site_values['server']['type_info']['interface_name']}\""
    peers_wireguard_print = pass_command_ssh(username,password,host,port,command)
    status=False
    for interface_wireguard_print in interfaces_wireguard_print.split("\r\n\r\n"):
        if find_arg_routeros_print(interface_wireguard_print,"name",site_values["server"]["type_info"]["interface_name"]):
            status=True
            islport = find_arg_routeros_print(interface_wireguard_print,"listen-port",site_values["server"]["port"])
            isprkey = find_arg_routeros_print(interface_wireguard_print,"private-key",cert_values["private_key"])
            ispukey = find_arg_routeros_print(interface_wireguard_print,"public-key",cert_values["public_key"])
            if (islport and isprkey and ispukey):
                listactivecert = []
                for peer_wireguard in peers_wireguard_print.split("\r\n\r\n"):
                    peer_exist = False
                    for cert in site_values["used_ips"]:
                        site_cert = json_file_read(f"{certs_path}/{sitename}/{site_values['used_ips'][cert]}.json")
                        if find_arg_routeros_print(peer_wireguard,"public-key",site_cert["public_key"]):
                            peer_exist = cert
                            isaddr = find_arg_routeros_print(peer_wireguard,"allowed-address",f"{cert}/32")
                            if (not isaddr):
                                command = f"/interface/wireguard/peers/set allowed-address={cert}/32 [/interface/wireguard/peers/find public-key=\"{site_cert['public_key']}\"]"
                                pass_command_ssh(username,password,host,port,command)
                    if (not peer_exist and peer_wireguard):
                        command = f"/interface/wireguard/peers/remove number={peer_wireguard.split()[0]}"
                        pass_command_ssh(username,password,host,port,command)
                    elif (peer_exist and peer_wireguard):
                        listactivecert.append(peer_exist)
                for cert in site_values["used_ips"]:
                    if (site_values["used_ips"][cert] != site_values["server"]["name"] and cert not in listactivecert):
                        site_cert = json_file_read(f"{certs_path}/{sitename}/{site_values['used_ips'][cert]}.json")
                        command = f"/interface/wireguard/peers/add allowed-address={cert}/32 public-key=\"{site_cert['public_key']}\" interface={site_values['server']['type_info']['interface_name']}"
                        pass_command_ssh(username,password,host,port,command)
            elif(not status):
                status="toupdate"
        elif(not status):
            status="toadd"
    if (status == "toupdate"):
        command=f"/interface/wireguard/set listen-port={site_values['server']['port']} private-key=\"{cert_values['private_key']}\" numbers={site_values['server']['type_info']['interface_name']}"
        pass_command_ssh(username,password,host,port,command)
        deploy_wireguard_configuration_routeros(password)
    elif(status == "toadd"):
        command=f"/interface/wireguard/add listen-port={site_values['server']['port']} private-key=\"{cert_values['private_key']}\" name={site_values['server']['type_info']['interface_name']}"
        pass_command_ssh(username,password,host,port,command)
        deploy_wireguard_configuration_routeros(password)
    serveur_wg_private_ip = get_server_private_ip(site_values)
    command=f"/ip/address/print detail where interface ={site_values['server']['type_info']['interface_name']} and address=\"{serveur_wg_private_ip}\""
    ip_addr_list_print = pass_command_ssh(username,password,host,port,command)
    for ip_addr_print in ip_addr_list_print.split("\r\n\r\n"):
        if not find_arg_routeros_print(ip_addr_print,"address",serveur_wg_private_ip):
            command=f"/ip/address/add interface={site_values['server']['type_info']['interface_name']} address=\"{serveur_wg_private_ip}\""
            pass_command_ssh(username,password,host,port,command)
              
def find_arg_routeros_print(printv,valuename,value):
    for arg in printv.split():
        if arg.split("=")[0] == valuename:
            if ((arg.split("=")[1] == value) or (re.findall('"([^"]*)"', arg)[0] == value)) :
                return(True)
    return(False)

def get_server_private_ip(site_values):
    for ip_addr_wg in site_values["used_ips"]:
        if site_values["server"]["name"] == site_values["used_ips"][ip_addr_wg]:
            return(ip_addr_wg)

def generate_conf_files():
    site_values = json_file_read(f"{sites_path}/{sitename}.json")
    serv_cert_values = json_file_read(f"{certs_path}/{sitename}/{site_values['server']['name']}.json")
    for file in (os.listdir(f"{exports_path}{sitename}/")):
        os.remove(f"{exports_path}{sitename}/{file}")
    for cert in site_values["used_ips"]:
        client_cert_values = json_file_read(f"{certs_path}/{sitename}/{site_values['used_ips'][cert]}.json")
        env = Environment(loader=FileSystemLoader( templates_path))
        template = env.get_template("wireguard_client.conf.j2")
        allowips=site_values['subnet']
        for ip in site_values["client_allowed_ip"]:
            allowips = f"{allowips},{ip}"
        values={"address":cert,"privateKey":client_cert_values["private_key"],"publicKey":serv_cert_values["public_key"],"allowIPs":allowips,"serverIP":site_values["server"]["IP"],"serverPort":site_values["server"]["port"]}
        with io.open(f"{exports_path}/{sitename}/{site_values['used_ips'][cert]}.conf", 'w',encoding='utf8') as f:
            f.write(template.render(value=values))
       
def print_wireguard_exported_conf():
    if os.path.exists(f"{exports_path}/{sitename}/{sys.argv[2]}.conf"):
        with open(f"{exports_path}/{sitename}/{sys.argv[2]}.conf", "r") as exportedfile:
            conf = exportedfile.read()
        print(conf)
    else:
        print(f"Le fichier {sys.argv[2]}.conf n'existe pas")

def print_wireguard_values():
    site_values = json_file_read(f"{sites_path}/{sitename}.json")
    print("CONFIGURATION DU SITE :")
    print(json.dumps(site_values,indent = 4))
    for ip in site_values["used_ips"]:
        cert_values = json_file_read(f"{certs_path}/{sitename}/{site_values['used_ips'][ip]}.json")
        print(f"JEU DE CLÉS POUR {site_values['used_ips'][ip]} :")
        print(json.dumps(cert_values,indent = 4))
        
def router():
    listcmd = {"generate-cert":3,"delete-cert":3,"generate-conf":2,"deploy-conf":2,"print-exported-conf":3,"print-global-conf":2}
    if len(sys.argv) < 2 or not sys.argv[1] in listcmd or not len(sys.argv)==listcmd[sys.argv[1]]:
        print(f"Usage: {__file__.split('/')[len(__file__.split('/'))-1]} OBJECT [name]")
        print(f"OBJECT :")
        print(f"        generate-cert [name]")
        print(f"        delete-cert [name]")
        print(f"        generate-conf")
        print(f"        deploy-conf")
        print(f"        print-exported-conf [name]")
        print(f"        print-global-conf")
    else:
        if sys.argv[1] == "generate-cert" :
            print()
            generate_wireguard_cert(sys.argv[2])
            add_wireguard_host(sys.argv[2])
        elif sys.argv[1] == "generate-conf":
            generate_conf_files()
        elif sys.argv[1] == "delete-cert":
            delete_wireguard_cert(sys.argv[2])
            del_wireguard_host(sys.argv[2])
        elif sys.argv[1] == "deploy-conf":
            deploy_wireguard_configuration_routeros(getpass(f"Mot de passe du routeur du site : "))
        elif sys.argv[1] == "print-global-conf":
            print_wireguard_values()
        elif sys.argv[1] == "print-exported-conf":
            print_wireguard_exported_conf()
sitename = get_sitename()
router()
