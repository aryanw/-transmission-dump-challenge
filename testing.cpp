#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#define _BSD_SOURCE
#include <netdb.h>
#include <functional>
#include <cstring>
#include <string>
#include <fstream>
#include <bitset>
#include <bit>
#include <climits>
#include <math.h>

#define PORT 2323

typedef unsigned int UInt32;

using namespace std;
bool utf8_check_is_valid(const string& string);
bool ReadXBytes(int socket, UInt32 x, void* buffer);
bool compareCheckSum(UInt32 chk,UInt32 seq,UInt32 len,char *buffer);
string repeat(string s, int n);
bool saveRawFile(ofstream fw,string dest,void *buff, UInt32 length);


int main(int argc, char const* argv[])
{
	// extract the ip
	hostent* myhostent = gethostbyname("challenge.airtime.com");
	string ip_airtime;
    if (!myhostent)
    {
        cerr << "gethostbyname() failed" << "\n";
    }
    else
    {
        cout << "Host name: " << myhostent->h_name << "\n";

        char ip[INET6_ADDRSTRLEN];
        for (UInt32 i = 0; myhostent->h_addr_list[i] != NULL; ++i)
        {
            cout << "Host ip: " << inet_ntop(myhostent->h_addrtype, myhostent->h_addr_list[i], 
                        ip, sizeof(ip)) << "\n";
			ip_airtime = ip;
        }
    }
	int sock = 0;
	struct sockaddr_in serv_addr;

	//  create socket
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Socket creation error \n");
		return -1;
	}
	

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	//  Convert IPv4 and IPv6 addresses from text to binary
	if (inet_pton(AF_INET, ip_airtime.c_str(), &serv_addr.sin_addr) <= 0) {
		cout << "\nInvalid address/ Address not supported \n";
		return -1;
	}

	if (connect(sock, (struct sockaddr*)&serv_addr,
                sizeof(serv_addr))  < 0) {
		printf("\nConnection Failed \n");
		return -1;
	}

    //  start listening
	char response_one[1024] = { 0 };
	int valread1 = read(sock, response_one, 1024);
	cout << "Recieved-- bytes: "<< valread1 << ", message:" <<response_one << "\n";

    //  extract challenge number string
    char *t;
	string challenge_string;
    for (t = response_one+6; *t != '\0'; t++) {
		challenge_string  = challenge_string + *t;
    }
	
	//  sending identification packet
	string str2 = "IAM:"+challenge_string.substr(0,challenge_string.length()-1)+":aryanwagadre@gmail.com:at\n";
	const char* message_two = str2.c_str();
	char response_two[1024] = { 0 };
	
    cout << "Sent--     : " << str2 << "\n";
	send(sock, message_two, strlen(message_two), 0);
	int valread2 = read(sock, response_two, 1024);
    cout << "Recieved-- bytes: "<< valread2 << ", message: " <<response_two << "\n";
    
	// start recieving packets
	UInt32 seq = 0;
	UInt32 chk = 0;
	UInt32 len = 0;

	int power = pow(2,11);
	char buffer[power] = { 0 }; // main buffer of length 2048
	char *bufferp = buffer;     // pointer to buffer
	bool streamFlag = true;     // return value of ReadXBytes
	
	int totalHIts = 0;          // number of checksum hits
	int packets = 0;            // total packets recieved
	bool verify;                // checksum compare return value
	int maxLen = 0;             // debugging variable: biggest len in header
                                //      of all acceptable packets

    cout << "Listening to stream" << "\n";
	while (streamFlag) {
		packets++;
		seq = 0;
		chk = 0;
		len = 0;
		
		streamFlag = ReadXBytes(sock, sizeof(seq), (void*)(&seq));  // read seq, chk, len
		if (!streamFlag) { 
			break;
		}
		streamFlag = ReadXBytes(sock, sizeof(chk), (void*)(&chk));
		streamFlag = ReadXBytes(sock, sizeof(len), (void*)(&len));
		
		len = htonl(len);                                           // convert to system endian
		memset(buffer,0,sizeof(buffer));                            // reset buffer
		streamFlag = ReadXBytes(sock, len, (void*)bufferp);         // read message
		verify = compareCheckSum(chk,seq,len,buffer);               // validate checksums
		if (verify) {                                               // if checksum match, 
                                                                    //     create a .raw file
			if (len > maxLen) {                                     // update maxLen if bigger
				maxLen = len;
			}
			totalHIts++;
			seq = htonl(seq);                                       
			string a = to_string(seq);                              // define file name
			string dest = a + ".raw";
			                                                        // save binary data in the file 
			ofstream binaryFile (dest, ios::out | ios::binary | ios::app);
			binaryFile.write (bufferp, len);
			binaryFile.close();
			 
		}
		
		
	} 
    cout << "total packets recieved:" << packets << "\n";
	cout << "total hits:" << totalHIts << "\n";
	cout << "max length of verified packets: " << maxLen << "\n\n";

    // extract files from the current directory and append in raw file
	cout << "starting file creation \n";
    string destination = "airtimeChallengeRaw.raw";
    const int result = remove( destination.c_str() );                       // delete raw file if exists
    if( result != 0 ){
        printf( "%s: \n", strerror( errno ));
    } 
    else {
        printf("deleted previous instance of airtimeChallengeRaw.raw\n");
    }
	for (int index = 0; index < totalHIts; index++) {                       // loop over all raw file,
		string a = to_string(index);                                        //      extract
		string src = a + ".raw";                                            //      and append


		ifstream input( src, ios::in | ios::binary );                       // open input
		ofstream output( destination, ios::out | ios::binary |ios::app);    // open output

		copy(                                                               // copy
			istreambuf_iterator<char>(input), 
			istreambuf_iterator<char>( ),
			ostreambuf_iterator<char>(output));
        const int result = remove( src.c_str() );                           // delete the input file
        if( result != 0 ){
            printf( "%s\n", strerror( errno ) );
        } 

	}
	cout << "ending file creation \n";
    cout << "file created output.raw \n";

}

/**
 * method reads x bytes from recieved packet from a socket and places into buffer 
 *
 */

bool ReadXBytes(int socket, UInt32 x, void* buffer)
{
	int bytesRead = 0;
    int result;
    while (bytesRead < x)
    {
        result = read(socket, (void*)((char*)buffer + bytesRead), x - bytesRead);
		if (result < 1 )
        {
			cout << "end of stream "<< "\n";
			return false;
        }
        if (result < 0 )
        {
            // Throw  error.
			cout << "Error in listening "<< result << "\n";
			return false;
        }
        bytesRead += result;
    }
	return true; 
}

/**
 * method calculates and compares checksums
 *
 */

bool compareCheckSum(UInt32 chk,UInt32 seq,UInt32 len,char *buffer) {
	
	UInt32 temp;                                                        // 4 byte buffer
	int bytesRead = 0;
	while (len) {
		
        if (len < 4) {
            
			temp = 0;                                                   // clear temp
			memcpy((void*)&temp,(((const char*)buffer)+bytesRead),len); // memcpy remaining bytes 
                                                                        //      into temp
			
			string s = repeat("AB",4-len);                              // create 0xAB padding
			UInt32 padding = stoul(s, nullptr, 16);                     
			padding = padding << (len*8);
			padding = (temp|padding);
			
			seq = seq ^ padding;                                        // xor
			len = 0;
            // cout << bitset<32>(padding) << " padding \n";
			
        } 
		else {
			temp = 0;                                                   // clear temp
			memcpy((void*)&temp,(((const char*)buffer)+bytesRead),4);   // memcpy remaining bytes
                                                                        //      into temp
			seq = seq ^ temp;                                           // xor
			len = len -4;                                               
			bytesRead=bytesRead+4;
		}
    }
	
	return chk == seq; 
	
}
/**
 * method repeats a basic_string
 *
 */
string repeat(string s, int n)
{
    // Copying given string to temporary string.
    string s1 = s;
 
    for (int i=1; i<n;i++)
        s += s1; // Concatenating strings
 
    return s;
}

/**

 * method checks if a string is a valid UTF8 string
 *
 * taken from: http://www.zedwood.com/article/cpp-is-valid-utf8-string-function
 *
 */
bool utf8_check_is_valid(const string& string)
{
    int c,i,ix,n,j;
    for (i=0, ix=string.length(); i < ix; i++)
    {
        c = (unsigned char) string[i];
        //if (c==0x09 || c==0x0a || c==0x0d || (0x20 <= c && c <= 0x7e) ) n = 0; // is_printable_ascii
        if (0x00 <= c && c <= 0x7f) n=0; // 0bbbbbbb
        else if ((c & 0xE0) == 0xC0) n=1; // 110bbbbb
        else if ( c==0xed && i<(ix-1) && ((unsigned char)string[i+1] & 0xa0)==0xa0) return false; //U+d800 to U+dfff
        else if ((c & 0xF0) == 0xE0) n=2; // 1110bbbb
        else if ((c & 0xF8) == 0xF0) n=3; // 11110bbb
        //else if (($c & 0xFC) == 0xF8) n=4; // 111110bb //byte 5, unnecessary in 4 byte UTF-8
        //else if (($c & 0xFE) == 0xFC) n=5; // 1111110b //byte 6, unnecessary in 4 byte UTF-8
        else return false;
        for (j=0; j<n && i<ix; j++) { // n bytes matching 10bbbbbb follow ?
            if ((++i == ix) || (( (unsigned char)string[i] & 0xC0) != 0x80))
                return false;
        }
    }
    return true;
}


