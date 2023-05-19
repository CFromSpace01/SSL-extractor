/*
Author: Francisco Miguel B. Felicio
Year: 2023

Description:
	This program takes a PCAPNG file as an input and extracts the SSL certificate contained in the TLS layer. The program outputs one pem file for each SSL certifcate found in the input file.
	
Input: PCAPNG file
Output: SSL certificates contained in .pem files. Filename format: yymmdd_hhmmss_[common name of issuer].pem
*/

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define SSL3_MT_HANDSHAKE 0x16
// #define SSL3_MT_SERVER_HELLO 0x02
#define SSL3_MT_SERVER_HELLO_DONE 0x0E

#define LEN_OF_BYTES_OF_LEN 3

void extract_SSL_cert( const u_char *data, struct timeval ts )
{
    int TLS_len = (data[3] << 8) | data[4];
    int handshake_type = data[5]; // check if handshake type is certificate
    if( handshake_type != 0x0B )
    {
        return;
    }
    else{
        printf("Passed handhshake test\n");
    }

    u_char *ssl_buffer_data=0;
    uint64_t  handshake_len = (data[6] << 16) | (data[7] << 8) | data[8];
    uint64_t  all_certificate_len = (data[9] << 16) | (data[10] << 8) | data[11];

    // while not all certificates are processed, continue generating files
    // i starts at 11 because this is the index of the first certificate
    for( int i = 12; i < TLS_len ;) 
    {
        // get certificate len
        uint64_t  certificate_len = (data[i] << 16) | (data[i+1] << 8) | data[i+2];
        // printf("CERT len: %ld\n",certificate_len);
        ssl_buffer_data = malloc( certificate_len *sizeof(u_char));
        memcpy(ssl_buffer_data, data + (i + LEN_OF_BYTES_OF_LEN) , certificate_len);

        const unsigned char* const_data = (const unsigned char*) ssl_buffer_data;
        const unsigned char** ptr_to_const_data = &const_data;
        // get and print the cert
        X509 *cert = d2i_X509(NULL, ptr_to_const_data, (long)certificate_len);
        printf("Certificate: %p\n", cert);
        if (cert)
        {
            X509_NAME *name = X509_get_issuer_name(cert);
            if (name)
                printf("Issuer: %s\n", X509_NAME_oneline(name, NULL, 0));
            
            // Generate strings for filename
            char str_time[20];
            strftime(str_time, sizeof(str_time), "%Y%m%d_%H%M%S", localtime(&ts.tv_sec));

            X509_NAME* subject_name = X509_get_subject_name(cert);
            int index = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
            X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject_name, index);
            ASN1_STRING* common_name_asn1 = X509_NAME_ENTRY_get_data(entry);
            const unsigned char* common_name_str = ASN1_STRING_get0_data(common_name_asn1);
            char* common_name = (char*)common_name_str;

            // Generate filename
            char* filename = malloc(strlen(str_time) + strlen(common_name) + 5 + 1);
            strcpy(filename, str_time);
            strcat(filename, "_");
            strcat(filename, common_name);
            strcat(filename, ".pem");
            printf("final filename is: %s\n", filename);
            // Open the output file for writing the PEM-formatted certificate.
            FILE *pem_file = fopen(filename, "w");

            // Write the certificate in PEM format to the output file.
            PEM_write_X509(pem_file, cert);

            // Close the output file.
            fclose(pem_file);

            X509_free(cert);
        }
        i += certificate_len+  LEN_OF_BYTES_OF_LEN;
    }   
}// end of fxn

int main(int argc, char *argv[])
{
    const u_char *packet;
    struct pcap_pkthdr *header;

    pcap_t *handle;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "tcp port 443";
    bpf_u_int32 net;

    int i=0, ret;

    int isHandshakeGoing = 0;
    int isHelloStarted = 0;
    int isHelloOngoing = 0;

    int prev_ssl_len=0;
    int ssl_data_len=0;
    int ssl_header_len = 0;
    int expected_TLS_len = 0;

    const uint8_t *payload_data;
    const u_char *prev_ssl_data=0;
    u_char *buf_ssl_data;
    uint16_t payload_len;

    struct ip *ip_header;       // <- problematic datatypes
    struct tcphdr *tcp_header;
    int ethernet_header_size = sizeof(struct ether_header);

    int TLS_header_len = 0;
    
    // Initialization sequence
    SSL_library_init();

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcapng_file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open file %s: %s\n", argv[1], errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Loop through packets
    while ((ret = pcap_next_ex(handle, &header, &packet)) == 1) {
        // Extract the Ethernet header
        struct ether_header *ethernet_header = (struct ether_header *) packet;

        // Check if the packet is an IP packet
        if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP) {
            i++;
            continue;
        }
        
        // Extract IP header
        ip_header = (struct ip*)(packet + ethernet_header_size);

        // Check if the packet is a TCP packet
        if (ip_header->ip_p != IPPROTO_TCP) {
            i++;
            continue;
        }

        // Get IP header and TCP header from packet
        struct tcphdr *tcp_header = (struct tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
        tcp_header = (struct tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
        
        // this is to check if the middle of the next packets contain the 0x02 data at the start.
        if ( ( isHandshakeGoing == 1 ) && ( packet[0] == SSL3_MT_HANDSHAKE ) )
        {
            i++;
            isHelloStarted = 0;
            isHelloOngoing = 0;
            continue;
        }

        // Calculate sequence number, acknowledgement number, payload length, and payload data
        payload_len = ntohs(ip_header->ip_len) - sizeof(struct ip) - tcp_header->doff * 4; // 1st instance should just be 1,244 or 0x4DC
        payload_data = packet + sizeof(struct ether_header) + sizeof(struct ip) + tcp_header->doff * 4;
        
        // Check if the packet is an SSL/TLS packet 0x01BB
        if (ntohs(tcp_header->source) != 443) {
            i++;
            isHelloStarted = 0;
            isHelloOngoing = 0;
            continue;
        }

        if( ( isHandshakeGoing == 0) && ( payload_data[0] != SSL3_MT_HANDSHAKE ) )
        {
            i++;
            continue;
        }

        if( payload_data[5] == SSL3_MT_SERVER_HELLO || isHelloOngoing == 1 )
        {
            if( isHelloOngoing == 1)
            {
                isHelloStarted = 0;
            }
            else isHelloStarted = 1;
            isHandshakeGoing = 1;
        }
        else
        {
            // clear flags and variables when message 
            expected_TLS_len = 0;
            isHelloStarted = 0;
            isHelloOngoing = 0;
            
            prev_ssl_len = 0;
            prev_ssl_data = 0;

            i++;
            continue;
        }

        if( isHelloOngoing == 1)
        {
            ssl_header_len = 0;
        }
        else
        {
            // Extract the SSL/TLS header
            TLS_header_len = (payload_data[3] << 8) | payload_data[4];
            ssl_header_len = TLS_header_len + SSL3_RT_HEADER_LENGTH;
        }
        
        const u_char *ssl_data = payload_data;
        ssl_data_len = payload_len;

        if( isHelloStarted == 1){
            buf_ssl_data = (u_char*) malloc(ssl_data_len);
            memcpy(buf_ssl_data, ssl_data + ssl_header_len, ssl_data_len - ssl_header_len);

            expected_TLS_len = (buf_ssl_data[3] << 8) | buf_ssl_data[4];
            prev_ssl_data = buf_ssl_data;
            prev_ssl_len = ssl_data_len - ssl_header_len;

            isHelloStarted = 0;
            isHelloOngoing = 1;
        }
        else if ( isHelloOngoing == 1)
        {
            buf_ssl_data = (u_char*) malloc(prev_ssl_len + ssl_data_len);

            // append new instance of SSL data
            memcpy(buf_ssl_data, prev_ssl_data, prev_ssl_len);
            // append old instance of SSL data
            memcpy(buf_ssl_data + prev_ssl_len, ssl_data, ssl_data_len);

            prev_ssl_data = buf_ssl_data;
            prev_ssl_len = prev_ssl_len + ssl_data_len;
        }
        else
        {
            prev_ssl_len = 0;
            prev_ssl_data = 0;
            return 0;
        }

        if( expected_TLS_len <= prev_ssl_len )
        {
            // Attempt to extract SSL certs then output to file.
            extract_SSL_cert( buf_ssl_data, header->ts );
            isHandshakeGoing = 0;
        }

        i++;
    }//end of while

    free(buf_ssl_data);
    pcap_close(handle);

    return 0;
}
