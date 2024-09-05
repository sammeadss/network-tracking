import dpkt
import socket
import pygeoip

# Initialize the GeoIP database from GeoLiteCity.dat to get geographical locations from IP addresses
gi = pygeoip.GeoIP('GeoLiteCity.dat')

def main():
    # Open the pcap file containing network traffic data
    f = open('wire.pcap', 'rb')
    
    # Initialize the pcap reader to parse the file
    pcap = dpkt.pcap.Reader(f)
    
    # Define the KML (Keyhole Markup Language) headers and footers for Google Earth visualization
    kmlheader = '<?xml version="1.0" encoding="UTF-8"?> \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'\
                '<Style id="transBluePoly">' \
                '<LineStyle>' \
                '<width>1.5</width>' \
                '<color>501400E6</color>' \
                '</LineStyle>' \
                '</Style>'
    kmlfooter = '</Document>\n</kml>\n'
    
    # Combine the KML document header, content (IP-based locations), and footer
    kmldoc = kmlheader + plotIPs(pcap) + kmlfooter
    
    # Print the final KML document to the console for viewing or saving to a file
    print(kmldoc)

def plotIPs(pcap):
    # Initialize an empty string to store KML points
    kmlPts = ''
    
    # Loop through each packet in the pcap file
    for (ts, buf) in pcap:
        try:
            # Extract Ethernet and IP layer data from the packet
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            
            # Convert source and destination IP addresses to readable format
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            
            # Generate KML content for the destination and source IP addresses
            KML = retKML(dst, src)
            
            # Append the generated KML content to the kmlPts string
            kmlPts = kmlPts + KML
        except:
            # Skip packet if any errors occur (e.g., not an IP packet)
            pass
    
    # Return the combined KML points for all packets
    return kmlPts

def retKML(dstip, srcip):
    # Look up the geographical location of the destination and source IP addresses
    dst = gi.record_by_name(dstip)
    src = gi.record_by_name('x.xxx.xxx.xxx')  # Replace this with the actual source IP address
    
    try:
        # Extract latitude and longitude from the GeoIP records for both destination and source
        dstlongitude = dst['longitude']
        dstlatitude = dst['latitude']
        srclongitude = src['longitude']
        srclatitude = src['latitude']
        
        # Create the KML placemark for the IP connection between source and destination
        kml = (
            '<Placemark>\n'
            '<name>%s</name>\n'  # Name of the placemark is the destination IP address
            '<extrude>1</extrude>\n'
            '<tessellate>1</tessellate>\n'
            '<styleUrl>#transBluePoly</styleUrl>\n'
            '<LineString>\n'
            '<coordinates>%6f,%6f\n%6f,%6f</coordinates>\n'  # Coordinates for source and destination
            '</LineString>\n'
            '</Placemark>\n'
        ) % (dstip, dstlongitude, dstlatitude, srclongitude, srclatitude)
        
        # Return the KML placemark for this IP connection
        return kml
    except:
        # Return an empty string if any error occurs during GeoIP lookup
        return ''

# If the script is executed (not imported as a module), call the main function
if __name__ == '__main__':
    main()