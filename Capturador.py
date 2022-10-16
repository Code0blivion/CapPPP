import sys
import scapy.all as scapy
from collections import Counter

def main():

    while True:

        print("")
        print("")
        print("Capturador de tramas PPP (Point to Point Protocol)")
        print("Elija una de las siguientes opciones: ")
        print("1- Capturar un número fijo de paquetes")
        print("2- Capturar por un tiempo determinado (Los resultados se guardarán en un archivo pcap)")
        print("3- Salir de la aplicacion")

        opcion = input();
        contador_paquetes = Counter()
        capturas=[]


        if(opcion=="3"):
            print("SALIENDO DEL CAPTURADOR. HASTA LUEGO")
            break

        if(opcion!="1" and opcion!="2"):
            print("Seleccion incorrecta. Regresando al menú principal")


        if(opcion=="1"):

            while True:

                print("")
                print("")
                contador_paquetes.clear()
                capturas.clear()
                ent=input("Ingrese el número de capturas que desee realizar: ")
                numcapt=int(ent)

                if(numcapt>0):
        
                    def imprimirTrama(packet):
                        capturas.append(packet)
                        key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                        contador_paquetes.update([key])
                        print("Paquete #"+str(sum(contador_paquetes.values()))+" "+packet.summary())


                    print("Capturando paquetes...")

                    scapy.sniff(prn=imprimirTrama,count=numcapt,store=1)

                    numpac = sum(contador_paquetes.values())

                    while True:
                        print("")
                        print("")
                        print("Se han capturado ",numcapt," paquetes")
                        print("")
                        print("Que desea realizar?")
                        print("1- Revisar la trama de un paquete especifico")
                        print("2- Guardar las capturas en un archivo pcap")
                        print("3- Salir del menu")

                        sel = input()

                        if(sel=="3"):
                            break


                        if(sel=="1"):
                            while True:
                                print("")
                                print("")
                                print("Ingrese el número del paquete al que desea ver los campos de su trama. " + "Rango de entradas disponibles (1,",numcapt,")")
                                numpack=input()


                                if(int(numpack)>0 and int(numpack)<=numcapt):
                                    a=capturas[int(numpack)-1]
                                    b=scapy.raw(a)
                                    print("Paquete # ",numpack,":")
                                    print("Trama protocolo PPP")
                                    c=scapy.DIR_PPP(b) 
                                    print(c.show())
                                    c=scapy.HDLC(b) 
                                    print(c.show())
                                    c=scapy.PPP(b) 
                                    print(c.show())
                                    c=scapy.PPPoE(b) 
                                    print(c.show())
                                    c=scapy.PPPoETag(b) 
                                    print(c.show())
                                    c=scapy.PPPoED_Tags(b) 
                                    print(c.show())
                                    c=scapy.PPPoED(b) 
                                    print(c.show())
                                    c=scapy.PPP_CHAP(b) 
                                    print(c.show())
                                    c=scapy.PPP_CHAP_ChallengeResponse(b) 
                                    print(c.show())
                                    c=scapy.PPP_ECP(b) 
                                    print(c.show())
                                    c=scapy.PPP_IPCP(b) 
                                    print(c.show())
                                    c=scapy.PPP_IPCP_Option_DNS1(b) 
                                    print(c.show())
                                    c=scapy.PPP_IPCP_Option_DNS2(b) 
                                    print(c.show())
                                    c=scapy.PPP_IPCP_Option_IPAddress(b) 
                                    print(c.show())
                                    c=scapy.PPP_LCP(b) 
                                    print(c.show())
                                    c=scapy.PPP_LCP_ACCM_Option(b) 
                                    print(c.show())
                                    c=scapy.PPP_LCP_Auth_Protocol_Option(b) 
                                    print(c.show())
                                    c=scapy.PPP_LCP_Callback_Option(b) 
                                    print(c.show())
                                    c=scapy.PPP_LCP_Code_Reject(b) 
                                    print(c.show())
                                    c=scapy.PPP_LCP_Echo(b) 
                                    print(c.show())
                                    c=scapy.PPP_LCP_Magic_Number_Option(b) 
                                    print(c.show())
                                    c=scapy.PPP_LCP_Option(b) 
                                    print(c.show())
                                    c=scapy.PPP_LCP_Protocol_Reject(b) 
                                    print(c.show())
                                    c=scapy.PPP_LCP_Quality_Protocol_Option(b) 
                                    print(c.show())
                                    c=scapy.PPP_PAP(b) 
                                    print(c.show())
                                    print("Desea seguir observando tramas de paquetes? Digite s para continuar o digite cualquier otra tecla para salir")
                                    dec=input()

                                    if(dec!="s"):
                                        break
                                
                                else:
                                    print("Numero de paquete fuera del rango")


                        if(sel=="2"):
                            print("Guardando paquetes capturados en archivo pcap....")
                            scapy.wrpcap("ResultadosCapturaPPP.pcap",capturas,append=True)
                            scapy.rdpcap("ResultadosCapturaPPP.pcap")
                            print("Archivo PCAP generado en la ubicación del ejecutable")

                        if(sel!="1" and sel !="2"):
                            print("Ha seleccionado una opcion incorrecta")

                else:
                    print("Seleccion incorrecta")
                    
                break

                
                
        else : 

            if(opcion=="2"):

                capturas.clear()

                print("Elija el tiempo de captura de paquetes (en segundos)")

                seg=input();

                def imprimirTrama(packet):
                    capturas.append(packet)
                    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
                    contador_paquetes.update([key])
                    print("Paquete #"+str(sum(contador_paquetes.values()))+" "+packet.summary())


                print("Capturando paquetes...")

                captura=scapy.sniff(prn=imprimirTrama,timeout=int(seg),store=1)

                for i in range(int(sum(contador_paquetes.values()))):
                    a=capturas[i]
                    b=scapy.raw(a)
                    c=scapy.DIR_PPP(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.HDLC(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPPoE(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPPoETag(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPPoED_Tags(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPPoED(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_CHAP(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_CHAP_ChallengeResponse(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_ECP(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_IPCP(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_IPCP_Option_DNS1(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_IPCP_Option_DNS2(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_IPCP_Option_IPAddress(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_LCP(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_LCP_ACCM_Option(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_LCP_Auth_Protocol_Option(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_LCP_Callback_Option(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_LCP_Code_Reject(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_LCP_Echo(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_LCP_Magic_Number_Option(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_LCP_Option(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_LCP_Protocol_Reject(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_LCP_Quality_Protocol_Option(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)
                    c=scapy.PPP_PAP(b) 
                    scapy.wrpcap("ResultadosCapturaPPP.pcap",c,append=True)

                scapy.rdpcap("ResultadosCapturaPPP.pcap")
                print("Archivo PCAP generado en la ubicación del ejecutable")

    sys.exit(0)
          
            
if __name__ == '__main__':
    main()




