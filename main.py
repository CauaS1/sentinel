from scapy.all import *
from datetime import datetime
import mariadb

conn = mariadb.connect(
    user="root",
    password="1234567",
    database="soc_lab" # try deleting this line to see if i can create a logic to check the exitence of this db
)   

cursor = conn.cursor() # Tool that talks to the database

def table_exists():
    cursor.execute("""
        SELECT EXISTS ( \
        SELECT 1 FROM INFORMATION_SCHEMA.TABLES \
        WHERE TABLE_SCHEMA = 'soc_lab' AND TABLE_NAME = 'network_events' \
        ) AS table_exists
    """)

    res = cursor.fetchall()
    res = res[0][0]

    if res == 0:
        cursor.execute("""CREATE TABLE network_events ( \
        packet INT AUTO_INCREMENT PRIMARY KEY, \
        timestamp VARCHAR(40),
        src_mac VARCHAR(20),
        dst_mac VARCHAR(20), 
        src_ip VARCHAR(15),
        dst_ip VARCHAR(15),
        protocol VARCHAR(8)) 
    """)


#packet = sniff(count=5)
#packet.summary()

def snifferFunction():
    # Sniffing the enp0s3 interface for IP packets, storing is true
    packets = sniff(iface="enp0s3", filter="ip", store=True, count=25) 
    protocol = ''

    # Fixing the timestamp from the response
    fixedTime = datetime.fromtimestamp(packets[1].time)

    
    le = len(packets)
    print(le)

    i = 0
    while i < le:
        # Converting the number related to the protocol to its formal name
        protoNum = packets[i][IP].proto

        if protoNum == 1:
            protocol = 'ICMP'
        elif protoNum == 6:
            protocol = 'TCP'
        elif protoNum == 17:
            protocol = 'TCP'

        timestp = str(fixedTime)
        src_mac = str(packets[i][Ether].src)
        dst_mac = str(packets[i][Ether].dst)
        src_ip = str(packets[i][IP].src)
        dst_ip = str(packets[i][IP].dst)
        protoc = str(protocol)

        # Inserting data into the database
            # You can use F-STRING to make the database unsafe for SQL Injection
        cursor.execute("""
        INSERT INTO network_events
        (timestamp, src_mac, dst_mac, src_ip, dst_ip, protocol)
            VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (timestp, src_mac, dst_mac, src_ip, dst_ip, protoc)
        )

        conn.commit() # Don't forget to commit the changes into the db

        i = i + 1

snifferFunction()
table_exists()


    


