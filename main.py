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

def test():
    response = sr1(IP(dst="192.168.1.12") / ICMP())

    # Fixing the timestamp from the response
    fixedTime = datetime.fromtimestamp(response.time)
    print(fixedTime)

    # Separating the data in a list && adding a timestamp
    response = f"{response}"
    splitedResp = response.split()
    
    splitedResp.insert(0, fixedTime)

    # separating into variables the: timestamp, source ip, destination ip and protocol used
    timestp = str(splitedResp[0])
    src_ip = str(splitedResp[4])
    dst_ip = str(splitedResp[6])
    protoc = str(splitedResp[3])

    print('==========================================')
    print('timestamp ', timestp)
    print('source ', src_ip)
    print('destination ', dst_ip)
    print('protocvol ', protoc)


    # Inserting data into the database
        # You can use F-STRING to make the database unsafe for SQL Injection
    cursor.execute("""
        INSERT INTO network_events
        (timestamp, src_ip, dst_ip, protocol)
        VALUES (%s, %s, %s, %s)
    """,
    (timestp, src_ip, dst_ip, protoc)
    )

    conn.commit() # Don't forget to commit the changes into the db


packets = sniff(iface="enp0s3", filter="ip", store=True, count=5) 
protocol = ''

print(packets[1].show())

fixedTime = datetime.fromtimestamp(packets[1].time)

print(fixedTime)
print(packets[1][Ether].src)
print(packets[1][Ether].dst)

print(packets[1][IP].src)
print(packets[1][IP].dst)
print(packets[1][IP].proto)

protoNum = packets[1][IP].proto

if protoNum == 1:
    protocol = 'ICMP'
elif protoNum == 6:
    protocol = 'TCP'
elif protoNum == 17:
    protocol = 'TCP'

table_exists()


    


