import os
import sys
import re
import matplotlib.pyplot as plt
import numpy as np
from mpl_toolkits.mplot3d import Axes3D
import math

#Autor: Nicolas Ricardo Enciso
#Solo funcional prototipo en distribuciones de Linux basados en Debian (Ubuntu, Kali, etc)
def menu():
    print ("-------------------------------------BIENVENIDO-------------------------------------------------------")
    print("              .--------.")
    print("'            / .------. \'")
    print("            / /        \ \'")
    print("            | |        | |")
    print("           _| |________| |_                -------------------------------------------------")
    print("          ' |_|        |_| '.              -------------------------------------------------")
    print("         '._____ ____ _____.'               *******    *******       ***    ****       ***  ")
    print("         |     .'____'.     |               ***        **           **  **  *** *      ***  ")
    print("         '.__.'.'    '.'.__.'               ***        **          **   **  ***  *     ***  ")
    print("         '.__  |      |  __.'               *******    **         **    **  ***   *    ***  ")
    print("         |   '.'.____.'.'   |                   ***    **        *********  ***    *   ***  ")
    print("         '.____'.____.'____.'                   ***    **       **      **  ***     *  ***  ")
    print("         '.________________.'               ******     ******  **       **  ***      * ***  ")
    print("                                           -------------------------------------------------")
    print("                                           -------------------------------------------------")
    print("---------------------------------------------------------------------------------------------------------")
    print ("*** Autor: Nicolas Ricardo Enciso  - Univeridad Nacional de Colombia -  Facultad de Ingenieria ")
    print ("*** Ingenieria de sistemas y computacion -- Bogota")
    print("***A continuacion, seleccione la opcion que desee para iniciar el analisis:  ")
    print("*** Presione A y luego ENTER para elegir el analisis en modo manual")
    print("*** Presione cualquier otra tecla y luego ENTER para salir del programa")
    modo = raw_input()
    if modo == 'a' or modo == 'A':
        IP = calculoRedManual(modoManual())
        tests = detectorSniffers(IP)
        MACaddrs = manInTheMiddleDetect()
        ordenamientoAnalisis(tests,MACaddrs)
        
    else:
        os.system('exit')
    

def lecturaIP():
    os.system('ifconfig > redes.txt')

def lecturaIPgrep():
    os.system("ip address | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})' > grepIP.txt")

def modoManual():
    lecturaIP()
    infoRed = ''
    print ("--------------------------------BIENVENIDO--------------------------------------")
    print("A continuacion se inicia el registro del equipo . . .")
    while len(infoRed) < 1:
        print ("> Interfaces de red:")
        print ("> Presione ENTER para continuar:  ")
        raw_input()
        os.system('ifconfig')
        print ("> De las interfaces, escriba la interfaz de red wifi que esta usando (wlan0,wlan1,etc) : \t")
        interfazRed = raw_input()
        print ("> Presione ENTER para continuar:  ")
        print ("---------------------------------------------------------------------------------")
        archivo = open('redes.txt','r')
        while True:
            linea = archivo.readline()
            if not linea: break
            if linea[0:len(interfazRed)] == interfazRed[0:len(interfazRed)]:
                infoRed = archivo.readline()
                break
        asegurado = re.match(r"inet",infoRed)
        if len(infoRed) < 1 or asegurado == "None":
            print("> Por favor ingrese de nuevo la interfaz de red wifi (interfaz no encontrada):  ")
            time.sleep(3)
    archivo.close()
    return infoRed
    


def calculoRedManual(infoRed):
    sal = (infoRed.strip().split(" "))
    indices = []
    IP = ""
    for i in range(len(sal)):
        try:
            num = int(sal[i][0])
            indices.append(i)
        except: ValueError, IndexError
    if len(indices) < 1:
        aux = infoRed.strip().split(" ")
        for casilla in aux:
            if "addr" in casilla:
                address = casilla.strip().split(":")
                IP = address[1]
            elif "Mask" in casilla:
                mascara = casilla.strip().split(":")
                newMask = mascara[1].strip().split('.')
                prefijo = 0
                for i in range(4):
                    sub = str(bin(int(newMask[i])))
                    for j in range(len(sub)):
                        if sub[j] == '1':
                            prefijo+=1
        IP = IP + ("/") + str(prefijo)
        print ("> Direccion IP de la red a la que se esta conectado:  ")
        print(IP)
    else:
        ipHost = sal[indices[0]]
        mask = sal[indices[1]]
        newIPhost = ipHost.strip().split('.')
        newMask = mask.strip().split('.')
        prefijo = 0
        for i in range(4):
            sub = str(bin(int(newMask[i])))
            for j in range(len(sub)):
                if sub[j] == '1':
                    prefijo+=1
        networkIP = ''
        for i in range(len(newIPhost)):
            if i != 3:
                networkIP = networkIP + str(newIPhost[i])+"."
            else:
                networkIP = networkIP + str(newIPhost[i])
        print ("> Direccion IP de la red a la que se esta conectado:  ")
        IP =  networkIP+ "/" + str(prefijo)
        print(IP)
        print ("> Presione ENTER para continuar:  ")
        raw_input()
    if len(IP) == 0:
        print("> No se ha podido determinar IP")
        print("> Por favor ingrese su IP y su mascara de red en prefijo EJ: 192.168.0.1/24 :")
        IP = raw_input()
    return IP

def modoAutomatico():
    lecturaIPgrep()
    archivo = open('grepIP.txt','r')
    for linea in archivo:
        triada = linea[0:3]
        if triada != '127':
            dirIP = linea
            break
    archivo.close()
    return dirIP

def detectorSniffers(IP):
    tests = []
    print ("----------------------------------------------------------------------------------")
    print("> Escaneando red por posibles intrusiones (sniffers) . . .")
    print("> Esto puede tardar varios minutos, no interrumpa la ejecucion hasta tener mensaje de confirmacion")
    print ("> Presione ENTER para inciar escaneo:  ")
    raw_input()
    print ("> Escaneando red . . .  ")
    comando = "nmap -sV --script=sniffer-detect "+str(IP)+" > nmap.txt"
    os.system(comando)
    print ("> Escaneo de red terminado")
    print("> Analizando datos . . . ")
    os.system( 'grep "tests" nmap.txt > tests.txt')
    archivo = open('tests.txt')
    if len(archivo.readline()) < 1:
        print ("> Error en la lectura de detector de sniffers, vuelva a ejecutar el programa")
        print ("> Cerrando programa . . . ")
        os.system('exit')
    else:
        print("> Analizado terminado.")
    archivo.close()
    resultados = open('tests.txt')
    for line in resultados:
        asegurado = re.match(r"tests",line)
        if asegurado == 'None':
            print(" > Error en la lectura de archivos de resultado nmap, inicie de nuevo el programa")
            print(" > Cerrando . . .")
            os.system('exit')
            break
        auxLIne = line.rpartition(':')
        aux2 = auxLIne[len(auxLIne)-1].partition('"')
        finalLine = aux2[len(aux2)-1].strip().split('"')
        testResultado = finalLine[0]
        tests.append(testResultado)
    return tests
        


def manInTheMiddleDetect():
    print("Inicio de escaneo tablas ARP . . .")
    devices = []
    MAC = []
    os.system('arp -a > ARPtabla.txt')
    archivo = open('ARPtabla.txt', 'r')
    for i in range(14):
        print("> Escaneo "+str(i)+" de 13")
        for line in archivo:
            if (line.find('.255') < 0):
                temp = line.partition('at')
                temp2 = temp[2]
                temp = temp2.rpartition('on')
                temp2 = temp[0]
                for i in devices:
                    if i == temp2:
                        print (">Alerta de posible ARP poisoning/spoofing")
                        print ("Direccion MAC posible atacante: " + temp2)
                        MAC.append(temp2)
                devices.append(temp2)
    print(" > Finalizado escaneo de tablas ARP")
    return MAC
                    
def ordenamientoAnalisis(tests, devices):
    os.system('> salida.txt')
    os.system('> badMACs.txt')
    salida = open('salida.txt','w')
    maccs = open('badMACs.txt','w')
    countPositivos = 0
    for unos in tests:
        for j in unos:
            if j == '1':
                countPositivos += 1
    lineaFinal = str(countPositivos)+" "+str(len(tests))+" "+str(len(devices))
    salida.write(lineaFinal)
    for i in devices:
        maccs.write(i)
    maccs.close()
    salida.close()

def entrenamiento():
    archivo = open('entrenoAtaque.txt','r')
    positivoSniffer = []
    positivoSnifferNeutro = []
    cantidadHosts = []
    cantidadHostsNeutro = []
    macs = []
    macsNeutro = []
    tipo = {}
    while True:
        linea = archivo.readline()
        if not linea: break
        linea = linea.split("|")
        positivoSniffer.append(int(linea[0]))
        cantidadHosts.append(int(linea[1]))
        macs.append(int(linea[2]))
        tipo[(int(linea[0]),int(linea[1]),int(linea[2]))] = 'ataque'    
    archivo.close()
    archivo = open('entrenoNeutral.txt','r')
    while True:
        linea = archivo.readline()
        if not linea: break
        linea = linea.split("|")
        positivoSnifferNeutro.append(int(linea[0]))
        cantidadHostsNeutro.append(int(linea[1]))
        macsNeutro.append(int(linea[2]))
        tipo[(int(linea[0]),int(linea[1]),int(linea[2]))] = 'neutro'
    archivo.close()
    archivo = open('salida.txt','r')
    (sniffer,hosts,macads) = archivo.readline().split(" ")
    sniffer = int(sniffer)
    hosts = int(hosts)
    macads = int(macads)
    fig = plt.figure()
    ax = fig.add_subplot(111, projection='3d')
    ax.scatter(positivoSniffer,cantidadHosts,macs, c='r',marker ='o')
    ax.scatter(positivoSnifferNeutro,cantidadHostsNeutro,macsNeutro, c='b',marker ='o')
    ax.scatter(sniffer,hosts,macads, c='g',marker ='o')
    ax.set_xlabel('Sniffer')
    ax.set_ylabel('cantidad Hosts')
    ax.set_zlabel('badMACs')
    plt.title('Ataques en WIFI - entrenamiento')
    plt.show()
    return tipo

def kneighbours(tipo):
    archivo = open('salida.txt','r')
    (sniffer,hosts,macs) = archivo.readline().split(" ")
    sniffer = int(sniffer)
    hosts = int(hosts)
    macs = int(macs)
    medidas = []
    for punto in tipo:
        distancia = math.sqrt( (sniffer - punto[0])**2 + (hosts - punto[1])**2 + (macs - punto[2])**2 )
        caso = tipo[punto]
        tipo[punto] = (caso,distancia)
        medidas.append(distancia)
    medidas.sort()
    votantes = medidas[0:7]
    finalistas = []
    for i in votantes:
        for punto in tipo:
            if i == tipo[punto][1]:
                finalistas.append(tipo[punto][0])
    ataques = 0
    neutrales = 0
    for i in finalistas:
        if i == "ataque":
            ataques += 1
        elif i == "neutro":
            neutrales += 1
    archivo.close()
    archivo = open('badMACs.txt','r')
    if ataques < neutrales:
        print(">>>>>>>>>>>>>>>>>>>Su dispositivo no se encuentra en peligro por el momento<<<<<<<<<<<<<<<<<<<")
        print("> Analisis de sniffer en la red: posibilidad de  "+str(sniffer)+" / 7")
        print("> Le recomendamos reiniciar su conexion a la red para mejor seguridad")
    elif ataques > neutrales:
        print(">>>>>>>>>>>>>>>>>><Su dispositivo esta bajo ataque, reinicie la conexion a su red<<<<<<<<<<<<<")
        if sniffer > 4:
            print("> Analisis de sniffer en la red: positivo para posible intrusion con grado de "+str(sniffer)+" / 7")
        if macs > 35:
            print("> Analisis de ataque MITM ARP Poisoning/Spoofing con "+str(macs)+" dispositivos que atacan")
            print("> MACs de dispositivos que lo estan atacando: ")    
            while True:
                linea = archivo.readline()
                if not linea: break
                print(linea)
    archivo.close()
    print("Finalizacion de ejecucion, ejecucion completada")
           
menu()
jun = entrenamiento()
kneighbours(jun)










